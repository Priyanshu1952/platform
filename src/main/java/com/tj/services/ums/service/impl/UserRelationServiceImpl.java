package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.UserRelationRequest;
import com.tj.services.ums.model.RelationshipType;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserRelation;
import com.tj.services.ums.repository.UserRelationRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.UserRelationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of UserRelationService with depth calculation and priority handling.
 * Implements the business rules for creating and managing user relations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserRelationServiceImpl implements UserRelationService {
    
    private final UserRelationRepository userRelationRepository;
    private final UserRepository userRepository;
    
    // Default priority for new relations
    private static final Integer DEFAULT_PRIORITY = 0;
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public UserRelation createUserRelation(UserRelationRequest request, String createdBy) {
        log.info("Creating user relation between {} and {} of type {}", 
                request.getUserId1(), request.getUserId2(), request.getRelationshipType());
        
        // Validate the request
        if (!validateRelationCreation(request)) {
            throw new IllegalArgumentException("Invalid relation creation request");
        }
        
        // Check if relation already exists
        if (relationExists(request.getUserId1(), request.getUserId2(), request.getRelationshipType())) {
            throw new IllegalStateException("Relation already exists between these users");
        }
        
        // Get user names for denormalization
        String userName1 = getUserName(request.getUserId1());
        String userName2 = getUserName(request.getUserId2());
        
        // Calculate depth based on business rules
        Integer depth = calculateDepth(request.getUserId1(), request.getRelationshipType());
        
        // Create the relation
        UserRelation relation = new UserRelation();
        relation.setUserId1(request.getUserId1());
        relation.setUserId2(request.getUserId2());
        relation.setUserName1(userName1);
        relation.setUserName2(userName2);
        relation.setRelationshipType(request.getRelationshipType());
        relation.setDepth(depth);
        relation.setPriority(request.getPriority() != null ? request.getPriority() : DEFAULT_PRIORITY);
        relation.setNotes(request.getNotes());
        relation.setCreatedBy(createdBy);
        relation.setActive(true);
        
        UserRelation savedRelation = userRelationRepository.save(relation);
        log.info("Created user relation with ID: {}", savedRelation.getId());
        
        return savedRelation;
    }
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public UserRelation updateUserRelation(Long relationId, UserRelationRequest request) {
        log.info("Updating user relation with ID: {}", relationId);
        
        UserRelation existingRelation = userRelationRepository.findById(relationId)
                .orElseThrow(() -> new IllegalArgumentException("Relation not found with ID: " + relationId));
        
        // Update allowed fields (excluding server-managed fields)
        existingRelation.setRelationshipType(request.getRelationshipType());
        existingRelation.setPriority(request.getPriority() != null ? request.getPriority() : DEFAULT_PRIORITY);
        existingRelation.setNotes(request.getNotes());
        
        // Recalculate depth if needed
        if (request.getRelationshipType().isHierarchical()) {
            Integer newDepth = calculateDepth(request.getUserId1(), request.getRelationshipType());
            existingRelation.setDepth(newDepth);
        }
        
        // Update denormalized names if user names changed
        updateDenormalizedNamesIfNeeded(existingRelation);
        
        return userRelationRepository.save(existingRelation);
    }
    
    @Override
    @Cacheable("user-relations")
    public Optional<UserRelation> getUserRelationById(Long relationId) {
        return userRelationRepository.findById(relationId);
    }
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public void deleteUserRelation(Long relationId) {
        log.info("Deleting user relation with ID: {}", relationId);
        UserRelation relation = userRelationRepository.findById(relationId)
                .orElseThrow(() -> new IllegalArgumentException("Relation not found with ID: " + relationId));
        relation.deactivate();
        userRelationRepository.save(relation);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<UserRelation> getUserRelations(String userId) {
        return userRelationRepository.findByUserId(userId);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<UserRelation> getUserRelationsByType(String userId, RelationshipType relationshipType) {
        return userRelationRepository.findByUserIdAndType(userId, relationshipType);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<UserRelation> getRelationsBetweenUsers(String userId1, String userId2) {
        return userRelationRepository.findByUserIds(userId1, userId2);
    }
    
    @Override
    public Page<UserRelation> getUserRelationsPage(String userId, Pageable pageable) {
        // This would need a custom implementation with pagination
        // For now, return all relations for the user
        List<UserRelation> relations = getUserRelations(userId);
        return Page.empty(pageable); // Placeholder
    }
    
    @Override
    @Cacheable("user-relationships")
    public List<String> getAllowedUserIds(String userId) {
        log.info("Getting allowed user IDs for user: {}", userId);
        Set<String> allowedUserIds = new HashSet<>();
        
        // Get all relations for the user
        List<UserRelation> relations = getUserRelations(userId);
        
        for (UserRelation relation : relations) {
            String otherUserId = relation.getOtherUser(userId);
            if (otherUserId != null && relation.isActive()) {
                // Add based on relationship type and business rules
                switch (relation.getRelationshipType()) {
                    case MANAGER_EMPLOYEE:
                        // Manager can access employee data
                        if (relation.getUserId1().equals(userId)) {
                            allowedUserIds.add(otherUserId);
                        }
                        break;
                    case AGENT_CLIENT:
                        // Agent can access client data
                        if (relation.getUserId1().equals(userId)) {
                            allowedUserIds.add(otherUserId);
                        }
                        break;
                    case PARTNER_ASSOCIATE:
                        // Partners can access each other's data
                        allowedUserIds.add(otherUserId);
                        break;
                    case PARENT_CHILD:
                        // Parent can access child data
                        if (relation.getUserId1().equals(userId)) {
                            allowedUserIds.add(otherUserId);
                        }
                        break;
                    case TEAM_MEMBER:
                        // Team members can access each other's basic data
                        allowedUserIds.add(otherUserId);
                        break;
                    case SUPERVISOR_SUBORDINATE:
                        // Supervisor can access subordinate data
                        if (relation.getUserId1().equals(userId)) {
                            allowedUserIds.add(otherUserId);
                        }
                        break;
                    case MENTOR_MENTEE:
                        // Mentor can access mentee data
                        if (relation.getUserId1().equals(userId)) {
                            allowedUserIds.add(otherUserId);
                        }
                        break;
                    case PEER:
                        // Peers can access each other's data
                        allowedUserIds.add(otherUserId);
                        break;
                }
            }
        }
        
        log.info("Found {} allowed user IDs for user: {}", allowedUserIds.size(), userId);
        return new ArrayList<>(allowedUserIds);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<String> getDirectReports(String managerId) {
        return userRelationRepository.findDirectReports(managerId);
    }
    
    @Override
    @Cacheable("user-relations")
    public Optional<String> getManager(String employeeId) {
        return userRelationRepository.findManager(employeeId);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<String> getTeamMembers(String teamLeadId) {
        return userRelationRepository.findTeamMembers(teamLeadId);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<String> getUsersAtDepth(String userId, Integer depth) {
        return userRelationRepository.findUsersAtDepth(userId, depth);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<String> getUsersAtMaxDepth(String userId, Integer maxDepth) {
        List<UserRelation> relations = userRelationRepository.findByUserIdAndMaxDepth(userId, maxDepth);
        return relations.stream()
                .map(relation -> relation.getOtherUser(userId))
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }
    
    @Override
    @Cacheable("user-relations")
    public Optional<UserRelation> getHighestPriorityRelation(String userId1, String userId2, RelationshipType type) {
        return userRelationRepository.findHighestPriorityRelation(userId1, userId2, type);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<UserRelation> getRelationsByPriorityRange(String userId, Integer minPriority, Integer maxPriority) {
        return userRelationRepository.findByUserIdAndPriorityRange(userId, minPriority, maxPriority);
    }
    
    @Override
    public boolean relationExists(String userId1, String userId2, RelationshipType relationshipType) {
        return userRelationRepository.relationExists(userId1, userId2, relationshipType);
    }
    
    @Override
    public long countRelationsByType(String userId, RelationshipType relationshipType) {
        return userRelationRepository.countByUserIdAndType(userId, relationshipType);
    }
    
    @Override
    @Cacheable("user-relations")
    public List<String> getTopLevelUsers() {
        return userRelationRepository.findTopLevelUsers();
    }
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public void updateDenormalizedNames(String userId, String newUserName) {
        log.info("Updating denormalized names for user: {} to: {}", userId, newUserName);
        
        // Update userName1 in relations where this user is userId1
        List<UserRelation> relationsAsUser1 = userRelationRepository.findByUserId(userId);
        for (UserRelation relation : relationsAsUser1) {
            if (relation.getUserId1().equals(userId)) {
                relation.setUserName1(newUserName);
            } else if (relation.getUserId2().equals(userId)) {
                relation.setUserName2(newUserName);
            }
        }
        userRelationRepository.saveAll(relationsAsUser1);
    }
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public void recalculateDepthForUser(String userId) {
        log.info("Recalculating depth for user: {}", userId);
        
        List<UserRelation> relations = getUserRelations(userId);
        for (UserRelation relation : relations) {
            if (relation.isHierarchical()) {
                Integer newDepth = calculateDepth(relation.getUserId1(), relation.getRelationshipType());
                relation.setDepth(newDepth);
            }
        }
        userRelationRepository.saveAll(relations);
    }
    
    @Override
    @CacheEvict(value = {"user-relations", "user-relationships"}, allEntries = true)
    public void deactivateRelations(String userId) {
        log.info("Deactivating all relations for user: {}", userId);
        
        List<UserRelation> relations = getUserRelations(userId);
        for (UserRelation relation : relations) {
            relation.deactivate();
        }
        userRelationRepository.saveAll(relations);
    }
    
    @Override
    public boolean validateRelationCreation(UserRelationRequest request) {
        // Basic validation
        if (request.getUserId1() == null || request.getUserId2() == null || 
            request.getRelationshipType() == null) {
            return false;
        }
        
        // Users should not be the same
        if (request.getUserId1().equals(request.getUserId2())) {
            return false;
        }
        
        // Validate that both users exist
        Optional<User> user1 = userRepository.findByUserId(request.getUserId1());
        Optional<User> user2 = userRepository.findByUserId(request.getUserId2());
        
        return user1.isPresent() && user2.isPresent();
    }
    
    @Override
    public boolean validateHierarchicalIntegrity(String userId1, String userId2, RelationshipType type) {
        if (!type.isHierarchical()) {
            return true; // Non-hierarchical relations don't need depth validation
        }
        
        // Check for circular references
        return !wouldCreateCircularReference(userId1, userId2, type);
    }
    
    // Private helper methods
    
    private String getUserName(String userId) {
        return userRepository.findByUserId(userId)
                .map(User::getName)
                .orElse("Unknown User");
    }
    
    private Integer calculateDepth(String userId, RelationshipType relationshipType) {
        if (!relationshipType.isHierarchical()) {
            return 0; // Non-hierarchical relations have depth 0
        }
        
        // For hierarchical relations, calculate depth based on userId1's existing depth
        Optional<String> managerId = getManager(userId);
        if (managerId.isPresent()) {
            // Find the manager's depth and add 1
            List<UserRelation> managerRelations = getUserRelationsByType(managerId.get(), RelationshipType.MANAGER_EMPLOYEE);
            if (!managerRelations.isEmpty()) {
                return managerRelations.get(0).getDepth() + 1;
            }
        }
        
        // If no manager found, this is a top-level user (depth 0)
        return 0;
    }
    
    private void updateDenormalizedNamesIfNeeded(UserRelation relation) {
        // Update userName1 if needed
        String currentUserName1 = getUserName(relation.getUserId1());
        if (!currentUserName1.equals(relation.getUserName1())) {
            relation.setUserName1(currentUserName1);
        }
        
        // Update userName2 if needed
        String currentUserName2 = getUserName(relation.getUserId2());
        if (!currentUserName2.equals(relation.getUserName2())) {
            relation.setUserName2(currentUserName2);
        }
    }
    
    private boolean wouldCreateCircularReference(String userId1, String userId2, RelationshipType type) {
        // Simple check for direct circular reference
        if (userId1.equals(userId2)) {
            return true;
        }
        
        // For hierarchical relations, check if this would create a loop
        if (type.isHierarchical()) {
            // Check if userId2 is already a manager of userId1
            Optional<String> currentManager = getManager(userId1);
            return currentManager.isPresent() && currentManager.get().equals(userId2);
        }
        
        return false;
    }
} 
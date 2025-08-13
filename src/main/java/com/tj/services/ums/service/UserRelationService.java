package com.tj.services.ums.service;

import com.tj.services.ums.dto.UserRelationRequest;
import com.tj.services.ums.model.RelationshipType;
import com.tj.services.ums.model.UserRelation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

/**
 * Service interface for managing user relations with hierarchical depth and priority support.
 */
public interface UserRelationService {
    
    // Basic CRUD operations
    UserRelation createUserRelation(UserRelationRequest request, String createdBy);
    UserRelation updateUserRelation(Long relationId, UserRelationRequest request);
    Optional<UserRelation> getUserRelationById(Long relationId);
    void deleteUserRelation(Long relationId);
    
    // Query operations
    List<UserRelation> getUserRelations(String userId);
    List<UserRelation> getUserRelationsByType(String userId, RelationshipType relationshipType);
    List<UserRelation> getRelationsBetweenUsers(String userId1, String userId2);
    Page<UserRelation> getUserRelationsPage(String userId, Pageable pageable);
    
    // Hierarchical operations
    List<String> getAllowedUserIds(String userId);
    List<String> getDirectReports(String managerId);
    Optional<String> getManager(String employeeId);
    List<String> getTeamMembers(String teamLeadId);
    List<String> getUsersAtDepth(String userId, Integer depth);
    List<String> getUsersAtMaxDepth(String userId, Integer maxDepth);
    
    // Priority operations
    Optional<UserRelation> getHighestPriorityRelation(String userId1, String userId2, RelationshipType type);
    List<UserRelation> getRelationsByPriorityRange(String userId, Integer minPriority, Integer maxPriority);
    
    // Business logic operations
    boolean relationExists(String userId1, String userId2, RelationshipType relationshipType);
    long countRelationsByType(String userId, RelationshipType relationshipType);
    List<String> getTopLevelUsers();
    
    // Utility operations
    void updateDenormalizedNames(String userId, String newUserName);
    void recalculateDepthForUser(String userId);
    void deactivateRelations(String userId);
    
    // Validation operations
    boolean validateRelationCreation(UserRelationRequest request);
    boolean validateHierarchicalIntegrity(String userId1, String userId2, RelationshipType type);
} 
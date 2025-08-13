package com.tj.services.ums.repository;

import com.tj.services.ums.model.RelationshipType;
import com.tj.services.ums.model.UserRelation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for managing user relations with depth and priority support.
 * Provides methods for hierarchical queries and relationship management.
 */
@Repository
public interface UserRelationRepository extends JpaRepository<UserRelation, Long> {
    
    /**
     * Find all relations involving a specific user
     */
    @Query("SELECT ur FROM UserRelation ur WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND ur.active = true")
    List<UserRelation> findByUserId(@Param("userId") String userId);
    
    /**
     * Find relations between two specific users
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "((ur.userId1 = :userId1 AND ur.userId2 = :userId2) OR " +
           "(ur.userId1 = :userId2 AND ur.userId2 = :userId1)) AND ur.active = true")
    List<UserRelation> findByUserIds(@Param("userId1") String userId1, @Param("userId2") String userId2);
    
    /**
     * Find relations of a specific type involving a user
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "(ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    List<UserRelation> findByUserIdAndType(@Param("userId") String userId, 
                                          @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find all users that have a specific relationship type with the given user
     */
    @Query("SELECT CASE " +
           "WHEN ur.userId1 = :userId THEN ur.userId2 " +
           "ELSE ur.userId1 " +
           "END FROM UserRelation ur " +
           "WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true " +
           "ORDER BY ur.priority DESC, ur.depth ASC")
    List<String> findRelatedUserIds(@Param("userId") String userId, 
                                   @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find all direct reports (employees) of a manager
     */
    @Query("SELECT ur.userId2 FROM UserRelation ur " +
           "WHERE ur.userId1 = :managerId AND " +
           "ur.relationshipType = 'MANAGER_EMPLOYEE' AND ur.active = true " +
           "ORDER BY ur.priority DESC, ur.depth ASC")
    List<String> findDirectReports(@Param("managerId") String managerId);
    
    /**
     * Find the manager of an employee
     */
    @Query("SELECT ur.userId1 FROM UserRelation ur " +
           "WHERE ur.userId2 = :employeeId AND " +
           "ur.relationshipType = 'MANAGER_EMPLOYEE' AND ur.active = true " +
           "ORDER BY ur.priority DESC LIMIT 1")
    Optional<String> findManager(@Param("employeeId") String employeeId);
    
    /**
     * Find all team members of a team lead
     */
    @Query("SELECT ur.userId2 FROM UserRelation ur " +
           "WHERE ur.userId1 = :teamLeadId AND " +
           "ur.relationshipType = 'TEAM_MEMBER' AND ur.active = true " +
           "ORDER BY ur.priority DESC, ur.depth ASC")
    List<String> findTeamMembers(@Param("teamLeadId") String teamLeadId);
    
    /**
     * Find relations by depth (for hierarchical queries)
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "(ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.depth = :depth AND ur.active = true " +
           "ORDER BY ur.priority DESC")
    List<UserRelation> findByUserIdAndDepth(@Param("userId") String userId, 
                                           @Param("depth") Integer depth);
    
    /**
     * Find relations with depth less than or equal to specified value
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "(ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.depth <= :maxDepth AND ur.active = true " +
           "ORDER BY ur.depth ASC, ur.priority DESC")
    List<UserRelation> findByUserIdAndMaxDepth(@Param("userId") String userId, 
                                              @Param("maxDepth") Integer maxDepth);
    
    /**
     * Find highest priority relation between two users
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "((ur.userId1 = :userId1 AND ur.userId2 = :userId2) OR " +
           "(ur.userId1 = :userId2 AND ur.userId2 = :userId1)) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true " +
           "ORDER BY ur.priority DESC LIMIT 1")
    Optional<UserRelation> findHighestPriorityRelation(@Param("userId1") String userId1, 
                                                      @Param("userId2") String userId2, 
                                                      @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Check if a relation exists between two users
     */
    @Query("SELECT COUNT(ur) > 0 FROM UserRelation ur " +
           "WHERE ((ur.userId1 = :userId1 AND ur.userId2 = :userId2) OR " +
           "(ur.userId1 = :userId2 AND ur.userId2 = :userId1)) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    boolean relationExists(@Param("userId1") String userId1, 
                          @Param("userId2") String userId2, 
                          @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Count relations of a specific type for a user
     */
    @Query("SELECT COUNT(ur) FROM UserRelation ur " +
           "WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    long countByUserIdAndType(@Param("userId") String userId, 
                             @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find relations created by a specific user
     */
    List<UserRelation> findByCreatedBy(String createdBy);
    
    /**
     * Find inactive relations
     */
    List<UserRelation> findByActiveFalse();
    
    /**
     * Find relations created within a date range
     */
    @Query("SELECT ur FROM UserRelation ur WHERE ur.createdOn BETWEEN :startDate AND :endDate")
    List<UserRelation> findByCreatedOnBetween(@Param("startDate") LocalDateTime startDate, 
                                             @Param("endDate") LocalDateTime endDate);
    
    /**
     * Find relations processed within a date range
     */
    @Query("SELECT ur FROM UserRelation ur WHERE ur.processedOn BETWEEN :startDate AND :endDate")
    List<UserRelation> findByProcessedOnBetween(@Param("startDate") LocalDateTime startDate, 
                                               @Param("endDate") LocalDateTime endDate);
    
    /**
     * Find relations by priority range
     */
    @Query("SELECT ur FROM UserRelation ur WHERE " +
           "(ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.priority BETWEEN :minPriority AND :maxPriority AND ur.active = true " +
           "ORDER BY ur.priority DESC")
    List<UserRelation> findByUserIdAndPriorityRange(@Param("userId") String userId, 
                                                   @Param("minPriority") Integer minPriority, 
                                                   @Param("maxPriority") Integer maxPriority);
    
    /**
     * Find top-level users (depth = 0)
     */
    @Query("SELECT DISTINCT ur.userId1 FROM UserRelation ur " +
           "WHERE ur.depth = 0 AND ur.active = true")
    List<String> findTopLevelUsers();
    
    /**
     * Find users at specific depth
     */
    @Query("SELECT DISTINCT CASE " +
           "WHEN ur.userId1 = :userId THEN ur.userId2 " +
           "ELSE ur.userId1 " +
           "END FROM UserRelation ur " +
           "WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.depth = :depth AND ur.active = true")
    List<String> findUsersAtDepth(@Param("userId") String userId, 
                                 @Param("depth") Integer depth);
} 
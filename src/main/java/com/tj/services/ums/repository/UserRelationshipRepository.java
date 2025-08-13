package com.tj.services.ums.repository;

import com.tj.services.ums.model.RelationshipType;
import com.tj.services.ums.model.UserRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for managing user relationships.
 * Provides methods for querying and managing user-to-user relationships.
 */
@Repository
public interface UserRelationshipRepository extends JpaRepository<UserRelationship, Long> {
    
    /**
     * Find all relationships involving a specific user
     */
    @Query("SELECT ur FROM UserRelationship ur WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND ur.active = true")
    List<UserRelationship> findByUserId(@Param("userId") String userId);
    
    /**
     * Find relationships between two specific users
     */
    @Query("SELECT ur FROM UserRelationship ur WHERE " +
           "((ur.userId1 = :userId1 AND ur.userId2 = :userId2) OR " +
           "(ur.userId1 = :userId2 AND ur.userId2 = :userId1)) AND ur.active = true")
    List<UserRelationship> findByUserIds(@Param("userId1") String userId1, @Param("userId2") String userId2);
    
    /**
     * Find relationships of a specific type involving a user
     */
    @Query("SELECT ur FROM UserRelationship ur WHERE " +
           "(ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    List<UserRelationship> findByUserIdAndType(@Param("userId") String userId, 
                                              @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find all users that have a specific relationship type with the given user
     */
    @Query("SELECT CASE " +
           "WHEN ur.userId1 = :userId THEN ur.userId2 " +
           "ELSE ur.userId1 " +
           "END FROM UserRelationship ur " +
           "WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    List<String> findRelatedUserIds(@Param("userId") String userId, 
                                   @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find all direct reports (employees) of a manager
     */
    @Query("SELECT ur.userId2 FROM UserRelationship ur " +
           "WHERE ur.userId1 = :managerId AND " +
           "ur.relationshipType = 'MANAGER_EMPLOYEE' AND ur.active = true")
    List<String> findDirectReports(@Param("managerId") String managerId);
    
    /**
     * Find the manager of an employee
     */
    @Query("SELECT ur.userId1 FROM UserRelationship ur " +
           "WHERE ur.userId2 = :employeeId AND " +
           "ur.relationshipType = 'MANAGER_EMPLOYEE' AND ur.active = true")
    Optional<String> findManager(@Param("employeeId") String employeeId);
    
    /**
     * Find all team members of a team lead
     */
    @Query("SELECT ur.userId2 FROM UserRelationship ur " +
           "WHERE ur.userId1 = :teamLeadId AND " +
           "ur.relationshipType = 'TEAM_MEMBER' AND ur.active = true")
    List<String> findTeamMembers(@Param("teamLeadId") String teamLeadId);
    
    /**
     * Find all subordinates in the hierarchy (recursive)
     * Using native SQL query for recursive CTE support
     */
    @Query(value = "WITH RECURSIVE subordinates AS (" +
           "SELECT ur.user_id2, 1 as level " +
           "FROM user_relationship ur " +
           "WHERE ur.user_id1 = :managerId AND ur.relationship_type = 'MANAGER_EMPLOYEE' AND ur.active = true " +
           "UNION ALL " +
           "SELECT ur.user_id2, s.level + 1 " +
           "FROM user_relationship ur " +
           "JOIN subordinates s ON ur.user_id1 = s.user_id2 " +
           "WHERE ur.relationship_type = 'MANAGER_EMPLOYEE' AND ur.active = true" +
           ") SELECT user_id2 FROM subordinates", nativeQuery = true)
    List<String> findAllSubordinates(@Param("managerId") String managerId);
    
    /**
     * Check if a relationship exists between two users
     */
    @Query("SELECT COUNT(ur) > 0 FROM UserRelationship ur " +
           "WHERE ((ur.userId1 = :userId1 AND ur.userId2 = :userId2) OR " +
           "(ur.userId1 = :userId2 AND ur.userId2 = :userId1)) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    boolean relationshipExists(@Param("userId1") String userId1, 
                              @Param("userId2") String userId2, 
                              @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Count relationships of a specific type for a user
     */
    @Query("SELECT COUNT(ur) FROM UserRelationship ur " +
           "WHERE (ur.userId1 = :userId OR ur.userId2 = :userId) AND " +
           "ur.relationshipType = :relationshipType AND ur.active = true")
    long countByUserIdAndType(@Param("userId") String userId, 
                             @Param("relationshipType") RelationshipType relationshipType);
    
    /**
     * Find relationships created by a specific user
     */
    List<UserRelationship> findByCreatedBy(String createdBy);
    
    /**
     * Find inactive relationships
     */
    List<UserRelationship> findByActiveFalse();
    
    /**
     * Find relationships created within a date range
     */
    @Query("SELECT ur FROM UserRelationship ur WHERE ur.createdAt BETWEEN :startDate AND :endDate")
    List<UserRelationship> findByCreatedAtBetween(@Param("startDate") java.time.LocalDateTime startDate, 
                                                 @Param("endDate") java.time.LocalDateTime endDate);
} 
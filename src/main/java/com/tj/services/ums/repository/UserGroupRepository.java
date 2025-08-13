package com.tj.services.ums.repository;

import com.tj.services.ums.model.UserGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for managing user groups and their members.
 * Provides methods for group management and member queries.
 */
@Repository
public interface UserGroupRepository extends JpaRepository<UserGroup, Long> {
    
    /**
     * Find group by name
     */
    Optional<UserGroup> findByGroupName(String groupName);
    
    /**
     * Find active groups
     */
    List<UserGroup> findByActiveTrue();
    
    /**
     * Find inactive groups
     */
    List<UserGroup> findByActiveFalse();
    
    /**
     * Find groups created by a specific user
     */
    List<UserGroup> findByCreatedBy(String createdBy);
    
    /**
     * Find groups created within a date range
     */
    List<UserGroup> findByCreatedOnBetween(LocalDateTime startDate, LocalDateTime endDate);
    
    /**
     * Check if group name exists
     */
    boolean existsByGroupName(String groupName);
    
    /**
     * Find groups by partial name match
     */
    @Query("SELECT ug FROM UserGroup ug WHERE ug.groupName LIKE %:groupName% AND ug.active = true")
    List<UserGroup> findByGroupNameContaining(@Param("groupName") String groupName);
    
    /**
     * Find groups that have a specific area role
     */
    @Query("SELECT DISTINCT ug FROM UserGroup ug JOIN ug.areaRoles ar " +
           "WHERE ar.roleCode = :roleCode AND ug.active = true AND ar.active = true")
    List<UserGroup> findByAreaRoleCode(@Param("roleCode") String roleCode);
    
    /**
     * Find groups that have any of the specified area roles
     */
    @Query("SELECT DISTINCT ug FROM UserGroup ug JOIN ug.areaRoles ar " +
           "WHERE ar.roleCode IN :roleCodes AND ug.active = true AND ar.active = true")
    List<UserGroup> findByAreaRoleCodes(@Param("roleCodes") List<String> roleCodes);
    
    /**
     * Find groups by functional area
     */
    @Query("SELECT DISTINCT ug FROM UserGroup ug JOIN ug.areaRoles ar " +
           "WHERE ar.functionalArea = :functionalArea AND ug.active = true AND ar.active = true")
    List<UserGroup> findByFunctionalArea(@Param("functionalArea") String functionalArea);
    
    /**
     * Count groups by active status
     */
    long countByActive(Boolean active);
    
    /**
     * Find groups with member count
     */
    @Query("SELECT ug, COUNT(ug.members) as memberCount FROM UserGroup ug " +
           "WHERE ug.active = true GROUP BY ug ORDER BY memberCount DESC")
    List<Object[]> findGroupsWithMemberCount();
    
    /**
     * Find groups created by user within date range
     */
    @Query("SELECT ug FROM UserGroup ug WHERE ug.createdBy = :createdBy " +
           "AND ug.createdOn BETWEEN :startDate AND :endDate")
    List<UserGroup> findByCreatedByAndDateRange(@Param("createdBy") String createdBy,
                                               @Param("startDate") LocalDateTime startDate,
                                               @Param("endDate") LocalDateTime endDate);
} 
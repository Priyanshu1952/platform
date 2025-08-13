package com.tj.services.ums.repository;

import com.tj.services.ums.model.AreaRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for managing area roles and their permissions.
 * Provides methods for role management and permission queries.
 */
@Repository
public interface AreaRoleRepository extends JpaRepository<AreaRole, Long> {
    
    /**
     * Find role by role code
     */
    Optional<AreaRole> findByRoleCode(String roleCode);
    
    /**
     * Find active roles
     */
    List<AreaRole> findByActiveTrue();
    
    /**
     * Find inactive roles
     */
    List<AreaRole> findByActiveFalse();
    
    /**
     * Find roles by functional area
     */
    List<AreaRole> findByFunctionalArea(String functionalArea);
    
    /**
     * Find active roles by functional area
     */
    List<AreaRole> findByFunctionalAreaAndActiveTrue(String functionalArea);
    
    /**
     * Check if role code exists
     */
    boolean existsByRoleCode(String roleCode);
    
    /**
     * Find roles by partial name match
     */
    @Query("SELECT ar FROM AreaRole ar WHERE ar.roleName LIKE %:roleName% AND ar.active = true")
    List<AreaRole> findByRoleNameContaining(@Param("roleName") String roleName);
    
    /**
     * Find roles by partial code match
     */
    @Query("SELECT ar FROM AreaRole ar WHERE ar.roleCode LIKE %:roleCode% AND ar.active = true")
    List<AreaRole> findByRoleCodeContaining(@Param("roleCode") String roleCode);
    
    /**
     * Find roles that are assigned to any user group
     */
    @Query("SELECT DISTINCT ar FROM AreaRole ar JOIN ar.userGroups ug " +
           "WHERE ug.active = true AND ar.active = true")
    List<AreaRole> findAssignedRoles();
    
    /**
     * Find roles that are not assigned to any user group
     */
    @Query("SELECT ar FROM AreaRole ar WHERE ar.active = true " +
           "AND ar NOT IN (SELECT DISTINCT ar2 FROM AreaRole ar2 JOIN ar2.userGroups ug WHERE ug.active = true)")
    List<AreaRole> findUnassignedRoles();
    
    /**
     * Find roles by multiple role codes
     */
    List<AreaRole> findByRoleCodeIn(List<String> roleCodes);
    
    /**
     * Find active roles by multiple role codes
     */
    List<AreaRole> findByRoleCodeInAndActiveTrue(List<String> roleCodes);
    
    /**
     * Count roles by active status
     */
    long countByActive(Boolean active);
    
    /**
     * Count roles by functional area
     */
    long countByFunctionalArea(String functionalArea);
    
    /**
     * Find roles with group count
     */
    @Query("SELECT ar, COUNT(ar.userGroups) as groupCount FROM AreaRole ar " +
           "WHERE ar.active = true GROUP BY ar ORDER BY groupCount DESC")
    List<Object[]> findRolesWithGroupCount();
    
    /**
     * Find roles by functional area with group count
     */
    @Query("SELECT ar, COUNT(ar.userGroups) as groupCount FROM AreaRole ar " +
           "WHERE ar.functionalArea = :functionalArea AND ar.active = true " +
           "GROUP BY ar ORDER BY groupCount DESC")
    List<Object[]> findRolesByFunctionalAreaWithGroupCount(@Param("functionalArea") String functionalArea);
    
    /**
     * Find all functional areas
     */
    @Query("SELECT DISTINCT ar.functionalArea FROM AreaRole ar WHERE ar.active = true")
    List<String> findAllFunctionalAreas();
    
    /**
     * Find roles that are commonly used together
     */
    @Query("SELECT ar1.roleCode, ar2.roleCode, COUNT(ug) as usageCount " +
           "FROM UserGroup ug JOIN ug.areaRoles ar1 JOIN ug.areaRoles ar2 " +
           "WHERE ar1.id < ar2.id AND ug.active = true AND ar1.active = true AND ar2.active = true " +
           "GROUP BY ar1.roleCode, ar2.roleCode ORDER BY usageCount DESC")
    List<Object[]> findCommonlyUsedRolePairs();
} 
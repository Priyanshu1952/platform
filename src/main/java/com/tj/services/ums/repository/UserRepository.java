package com.tj.services.ums.repository;

import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserRole;
import com.tj.services.ums.model.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // Basic finders
    Optional<User> findByEmail(String email);
    Optional<User> findByMobile(String mobile);
    Optional<User> findByUserId(String userId);
    Optional<User> findByEmployeeId(String employeeId);
    
    // Existence checks
    boolean existsByEmail(String email);
    boolean existsByMobile(String mobile);
    boolean existsByUserId(String userId);
    
    // Role-based queries
    List<User> findByRole(UserRole role);
    List<User> findByRoleIn(List<UserRole> roles);
    
    // Status-based queries
    List<User> findByStatus(UserStatus status);
    List<User> findByStatusIn(List<UserStatus> statuses);
    
    // Partner-based queries
    List<User> findByPartnerId(String partnerId);
    List<User> findByPartnerIdIn(List<String> partnerIds);
    
    // Parent-child relationships
    List<User> findByParentUserId(String parentUserId);
    List<User> findByParentUser(User parentUser);
    
    // Search queries with LIKE
    @Query("SELECT u FROM User u WHERE u.name LIKE %:name%")
    List<User> findByNameContaining(@Param("name") String name);
    
    @Query("SELECT u FROM User u WHERE u.email LIKE %:email%")
    List<User> findByEmailContaining(@Param("email") String email);
    
    @Query("SELECT u FROM User u WHERE u.employeeId LIKE %:employeeId%")
    List<User> findByEmployeeIdContaining(@Param("employeeId") String employeeId);
    
    // Date range queries
    List<User> findByCreatedOnBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<User> findByProcessedOnBetween(LocalDateTime startDate, LocalDateTime endDate);
    
    // Complex search query
    @Query("SELECT u FROM User u WHERE " +
           "(:name IS NULL OR u.name LIKE %:name%) AND " +
           "(:email IS NULL OR u.email = :email) AND " +
           "(:mobile IS NULL OR u.mobile = :mobile) AND " +
           "(:role IS NULL OR u.role = :role) AND " +
           "(:status IS NULL OR u.status = :status) AND " +
           "(:partnerId IS NULL OR u.partnerId = :partnerId) AND " +
           "(:parentUserId IS NULL OR u.parentUserId = :parentUserId)")
    Page<User> findUsersWithFilters(
        @Param("name") String name,
        @Param("email") String email,
        @Param("mobile") String mobile,
        @Param("role") UserRole role,
        @Param("status") UserStatus status,
        @Param("partnerId") String partnerId,
        @Param("parentUserId") String parentUserId,
        Pageable pageable
    );
    
    // Balance-related queries
    @Query("SELECT u FROM User u WHERE u.balance > :minBalance")
    List<User> findUsersWithBalanceGreaterThan(@Param("minBalance") Double minBalance);
    
    @Query("SELECT u FROM User u WHERE u.walletBalance > :minWalletBalance")
    List<User> findUsersWithWalletBalanceGreaterThan(@Param("minWalletBalance") Double minWalletBalance);
    
    // Verification status queries
    @Query("SELECT u FROM User u WHERE u.panInfo.verified = :verified")
    List<User> findByPanVerified(@Param("verified") Boolean verified);
    
    @Query("SELECT u FROM User u WHERE JSON_EXTRACT(u.additionalInfo, '$.customFields.aadhaarVerified') = :verified")
    List<User> findByAadhaarVerified(@Param("verified") String verified);
    
    @Query("SELECT u FROM User u WHERE JSON_EXTRACT(u.additionalInfo, '$.customFields.emailVerified') = :verified")
    List<User> findByEmailVerified(@Param("verified") String verified);
    
    // User relations queries
    @Query("SELECT ur FROM User u JOIN u.userRelations ur WHERE u.userId = :userId")
    List<User> findUserRelations(@Param("userId") String userId);
    
    // Sales user queries
    @Query("SELECT u FROM User u WHERE u.role = 'SALES_USER' AND u.status = 'ACTIVE'")
    List<User> findActiveSalesUsers();
    
    // Rail-specific queries
    // @Query("SELECT u FROM User u WHERE u.railAdditionalInfo IS NOT NULL AND JSON_EXTRACT(u.railAdditionalInfo, '$.railActive') = 'true'")
    // List<User> findActiveRailUsers();
    
    // Count queries
    long countByRole(UserRole role);
    long countByStatus(UserStatus status);
    long countByPartnerId(String partnerId);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdOn >= :startDate")
    long countUsersCreatedAfter(@Param("startDate") LocalDateTime startDate);
    
    // Emulation queries
    List<User> findByCanBeEmulated(Boolean canBeEmulated);
    List<User> findByEmulateUser(User emulateUser);
    
    // Custom update queries for specific fields
    @Query("UPDATE User u SET u.status = :status WHERE u.userId = :userId")
    void updateUserStatus(@Param("userId") String userId, @Param("status") UserStatus status);
    
    @Query("UPDATE User u SET u.balance = :balance WHERE u.userId = :userId")
    void updateUserBalance(@Param("userId") String userId, @Param("balance") Double balance);
    
    @Query("UPDATE User u SET u.walletBalance = :walletBalance WHERE u.userId = :userId")
    void updateUserWalletBalance(@Param("userId") String userId, @Param("walletBalance") Double walletBalance);
}

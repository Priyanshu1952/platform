package com.tj.services.ums.service;

import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserRole;
import com.tj.services.ums.model.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserService {
    
    // Basic CRUD operations
    User createUser(User user);
    User updateUser(User user);
    Optional<User> getUserById(Long id);
    Optional<User> getUserByUserId(String userId);
    Optional<User> getUserByEmail(String email);
    Optional<User> getUserByMobile(String mobile);
    void deleteUser(Long id);
    
    // Search and filter operations
    List<User> getAllUsers();
    Page<User> getUsersWithFilters(String name, String email, String mobile, 
                                  UserRole role, UserStatus status, 
                                  String partnerId, String parentUserId, 
                                  Pageable pageable);
    List<User> searchUsersByName(String name);
    List<User> getUsersByRole(UserRole role);
    List<User> getUsersByStatus(UserStatus status);
    List<User> getUsersByPartnerId(String partnerId);
    
    // User relationships
    List<User> getChildUsers(String parentUserId);
    List<User> getUserRelations(String userId);
    void addUserRelation(String userId1, String userId2);
    void removeUserRelation(String userId1, String userId2);
    
    // Verification operations
    void updatePanVerificationStatus(String userId, boolean verified);
    void updateAadhaarVerificationStatus(String userId, boolean verified);
    void updateEmailVerificationStatus(String userId, boolean verified);
    List<User> getPanVerifiedUsers();
    List<User> getAadhaarVerifiedUsers();
    List<User> getEmailVerifiedUsers();
    
    // Balance operations
    void updateUserBalance(String userId, Double balance);
    void updateUserWalletBalance(String userId, Double walletBalance);
    List<User> getUsersWithMinimumBalance(Double minBalance);
    
    // Status operations
    void updateUserStatus(String userId, UserStatus status);
    void activateUser(String userId);
    void deactivateUser(String userId);
    void suspendUser(String userId);
    
    // Emulation operations
    void enableEmulation(String userId);
    void disableEmulation(String userId);
    List<User> getEmulableUsers();
    
    // Rail operations
    List<User> getActiveRailUsers();
    void updateRailStatus(String userId, boolean active);
    
    // Sales operations
    List<User> getActiveSalesUsers();
    
    // Statistics and counts
    long getTotalUserCount();
    long getUserCountByRole(UserRole role);
    long getUserCountByStatus(UserStatus status);
    long getNewUsersCount(LocalDateTime since);
    
    // Validation operations
    boolean isEmailAvailable(String email);
    boolean isMobileAvailable(String mobile);
    boolean isUserIdAvailable(String userId);
    
    // Profile operations
    User updateUserProfile(String userId, com.tj.services.ums.model.UserProfile profile);
    User updateUserAdditionalInfo(String userId, com.tj.services.ums.model.UserAdditionalInfo additionalInfo);
    
    // Configuration operations
    User updateUserConfiguration(String userId, com.tj.services.ums.model.UserConfiguration configuration);
    
    // Migration helper methods
    User migrateFromAuthUser(com.tj.services.ums.model.AuthUser authUser);
    void syncUserData(String userId);
}

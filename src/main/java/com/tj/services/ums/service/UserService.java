package com.tj.services.ums.service;

import com.tj.services.ums.dto.UserUpdateRequest;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Comprehensive service for user management operations
 * Handles both AuthUser (authentication) and User (business logic) models
 */
public interface UserService {
    
    // AuthUser operations
    AuthUser getAuthUserById(UUID userId);
    Optional<AuthUser> getAuthUserByEmail(String email);
    AuthUser updateAuthUser(UUID userId, UserUpdateRequest request);
    AuthUser updateAuthUserSecurity(UUID userId, UserUpdateRequest request);
    
    // User operations (business logic)
    User getUserById(Long userId);
    User getUserByUserId(String userId);
    User updateUser(Long userId, UserUpdateRequest request);
    User updateUserByUserId(String userId, UserUpdateRequest request);
    
    // Combined operations
    UserUpdateRequest getUserUpdateRequest(UUID authUserId);
    UserUpdateRequest getUserUpdateRequestByUserId(String userId);
    
    // User relationship operations
    List<String> getAllowedUserIds(String userId);
    List<User> getUserRelations(String userId);
    
    // Search and query operations
    Optional<User> getUserByUserId(String userId, boolean includeRelations);
    List<User> searchUsers(String query);
    List<User> getUsersByRole(String role);
    List<User> getUsersByStatus(String status);
    
    // Bulk operations
    List<User> updateMultipleUsers(List<Long> userIds, UserUpdateRequest request);
    void deactivateUsers(List<Long> userIds);
    void activateUsers(List<Long> userIds);
    
    // Validation operations
    boolean isEmailAvailable(String email, UUID excludeUserId);
    boolean isMobileAvailable(String mobile, UUID excludeUserId);
    boolean isUserIdAvailable(String userId);
    
    // Security operations
    void lockUserAccount(UUID userId);
    void unlockUserAccount(UUID userId);
    void resetFailedAttempts(UUID userId);
    void updateLastPasswordChange(UUID userId);
    
    // Profile operations
    void updateUserProfile(UUID userId, UserUpdateRequest request);
    void updateUserAddress(UUID userId, UserUpdateRequest request);
    void updateUserContactInfo(UUID userId, UserUpdateRequest request);
    void updateUserKYCInfo(UUID userId, UserUpdateRequest request);
    
    // Verification operations
    void markEmailVerified(UUID userId);
    void markPanVerified(UUID userId);
    void markAadhaarVerified(UUID userId);
    
    // Financial operations
    void updateUserBalance(Long userId, Double newBalance);
    void updateUserWalletBalance(Long userId, Double newWalletBalance);
    void updateUserTotalBalance(Long userId, Double newTotalBalance);
}

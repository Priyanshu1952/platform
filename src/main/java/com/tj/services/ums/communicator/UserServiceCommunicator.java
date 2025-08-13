package com.tj.services.ums.communicator;

import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserProfile;

import java.util.List;

/**
 * Interface for communicating with external services that need user information.
 * This enables the UMS to act as a centralized user management service in a microservices architecture.
 */
public interface UserServiceCommunicator {
    
    /**
     * Get user by ID from external service perspective
     * @param userId the user ID
     * @return User object or null if not found
     */
    User getUserById(String userId);
    
    /**
     * Get list of user IDs that the given user is allowed to interact with
     * Based on user relationships, permissions, and business rules
     * @param userId the user ID
     * @return List of allowed user IDs
     */
    List<String> getAllowedUserIds(String userId);
    
    /**
     * Check if user has specific permission
     * @param userId the user ID
     * @param permission the permission to check
     * @return true if user has permission, false otherwise
     */
    boolean hasPermission(String userId, String permission);
    
    /**
     * Get user profile information
     * @param userId the user ID
     * @return UserProfile object
     */
    UserProfile getUserProfile(String userId);
    
    /**
     * Update user's last login timestamp
     * @param userId the user ID
     */
    void updateUserLastLogin(String userId);
    
    /**
     * Get users by role
     * @param role the role to filter by
     * @return List of users with the specified role
     */
    List<User> getUsersByRole(String role);
    
    /**
     * Get users by partner ID
     * @param partnerId the partner ID
     * @return List of users associated with the partner
     */
    List<User> getUsersByPartnerId(String partnerId);
    
    /**
     * Validate if user exists and is active
     * @param userId the user ID
     * @return true if user exists and is active, false otherwise
     */
    boolean isUserActive(String userId);
} 
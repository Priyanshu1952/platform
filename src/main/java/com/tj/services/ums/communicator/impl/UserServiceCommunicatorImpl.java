package com.tj.services.ums.communicator.impl;

import com.tj.services.ums.communicator.UserServiceCommunicator;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserProfile;
import com.tj.services.ums.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * Implementation of UserServiceCommunicator for microservice communication.
 * Provides caching and external service integration capabilities.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceCommunicatorImpl implements UserServiceCommunicator {
    
    private final UserService userService;
    
    @Override
    @Cacheable("user-profiles")
    public User getUserById(String userId) {
        log.debug("Getting user by ID: {}", userId);
        User user = userService.getUserByUserId(userId);
        return user;
    }
    
    @Override
    @Cacheable("user-relationships")
    public List<String> getAllowedUserIds(String userId) {
        log.debug("Getting allowed user IDs for user: {}", userId);
        return userService.getAllowedUserIds(userId);
    }
    
    @Override
    @Cacheable("user-permissions")
    public boolean hasPermission(String userId, String permission) {
        log.debug("Checking permission '{}' for user: {}", permission, userId);
        
        // Get user to check their role
        User user = getUserById(userId);
        if (user == null) {
            return false;
        }
        
        // Basic permission checking based on role
        switch (permission.toLowerCase()) {
            case "view_users":
                return user.getRole().name().contains("ADMIN") || 
                       user.getRole().name().contains("MANAGER");
            case "edit_users":
                return user.getRole().name().contains("ADMIN");
            case "delete_users":
                return user.getRole().name().contains("ADMIN");
            case "view_reports":
                return user.getRole().name().contains("ADMIN") || 
                       user.getRole().name().contains("MANAGER");
            case "manage_relationships":
                return user.getRole().name().contains("ADMIN") || 
                       user.getRole().name().contains("MANAGER");
            default:
                return false;
        }
    }
    
    @Override
    @Cacheable("user-profiles")
    public UserProfile getUserProfile(String userId) {
        log.debug("Getting user profile for user: {}", userId);
        User user = getUserById(userId);
        return user != null ? user.getUserProfile() : null;
    }
    
    @Override
    public void updateUserLastLogin(String userId) {
        log.debug("Updating last login for user: {}", userId);
        // This would typically update a last login timestamp
        // Implementation depends on the specific requirements
    }
    
    @Override
    @Cacheable("users-by-role")
    public List<User> getUsersByRole(String role) {
        log.debug("Getting users by role: {}", role);
        try {
            return userService.getUsersByRole(role);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid role: {}", role);
            return List.of();
        }
    }
    
    @Override
    @Cacheable("users-by-partner")
    public List<User> getUsersByPartnerId(String partnerId) {
        log.debug("Getting users by partner ID: {}", partnerId);
        // TODO: Implement partner-based user filtering
        // For now, return empty list as this method is not implemented in UserService
        return List.of();
    }
    
    @Override
    @Cacheable("user-active-status")
    public boolean isUserActive(String userId) {
        log.debug("Checking if user is active: {}", userId);
        User user = getUserById(userId);
        return user != null && user.getStatus() == com.tj.services.ums.model.UserStatus.ACTIVE;
    }
} 
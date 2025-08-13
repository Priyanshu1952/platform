package com.tj.services.ums.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Cache configuration for the UMS application.
 * Provides caching support for user profiles, relationships, and permissions.
 */
@Configuration
@EnableCaching
public class CacheConfig {
    
    /**
     * Primary cache manager using in-memory caching.
     * This provides fast access to frequently used data.
     */
    @Bean
    @Primary
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        
        // Define cache names for different types of data
        cacheManager.setCacheNames(java.util.Arrays.asList(
            "user-profiles",           // User profile data
            "user-relationships",      // User relationship data
            "user-permissions",        // User permission data
            "users-by-role",          // Users grouped by role
            "users-by-partner",       // Users grouped by partner
            "user-active-status",     // User active status
            "otp-tokens",             // OTP token data
            "device-info",            // Device information
            "auth-tokens"             // Authentication tokens
        ));
        
        return cacheManager;
    }
    
    /**
     * Cache configuration for user profiles.
     * User profiles are cached for 30 minutes by default.
     */
    @Bean("userProfileCacheManager")
    public CacheManager userProfileCacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        cacheManager.setCacheNames(java.util.Arrays.asList("user-profiles"));
        return cacheManager;
    }
    
    /**
     * Cache configuration for user relationships.
     * Relationships are cached for 15 minutes as they change less frequently.
     */
    @Bean("userRelationshipCacheManager")
    public CacheManager userRelationshipCacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        cacheManager.setCacheNames(java.util.Arrays.asList("user-relationships"));
        return cacheManager;
    }
    
    /**
     * Cache configuration for permissions.
     * Permissions are cached for 1 hour as they rarely change.
     */
    @Bean("permissionCacheManager")
    public CacheManager permissionCacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        cacheManager.setCacheNames(java.util.Arrays.asList("user-permissions"));
        return cacheManager;
    }
} 
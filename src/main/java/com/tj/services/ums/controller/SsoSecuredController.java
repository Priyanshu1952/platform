package com.tj.services.ums.controller;

import com.tj.services.ums.security.annotation.CustomRequestProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Example secured REST controller demonstrating SSO integration
 * with role-based access control using JWT tokens from Identity Provider.
 * 
 * This controller showcases various authorization patterns:
 * - Public endpoints (no authentication)
 * - Authenticated endpoints (valid token required)
 * - Role-based access control (ADMIN, AGENT, USER)
 * - Scope-based access control (OAuth2 scopes)
 * - Custom business logic authorization
 */
@RestController
@RequestMapping("/api/v1/sso")
@RequiredArgsConstructor
@Slf4j
public class SsoSecuredController {

    /**
     * Public endpoint - no authentication required
     * Accessible by anyone without a valid JWT token
     */
    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> getPublicInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("service", "TGS Microservice");
        response.put("version", "1.0.0");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Authenticated endpoint - requires valid JWT token
     * Any authenticated user can access this endpoint
     */
    @GetMapping("/secure/profile")
    @PreAuthorize("isAuthenticated()")
    @CustomRequestProcessor(areaRole = {"PROFILE_READ"})
    public ResponseEntity<Map<String, Object>> getUserProfile(Authentication authentication) {
        log.info("Accessing user profile for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User profile accessed successfully");
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        response.put("authenticated", authentication.isAuthenticated());
        response.put("authType", authentication.getClass().getSimpleName());
        
        return ResponseEntity.ok(response);
    }

    /**
     * User-level endpoint - requires USER, AGENT, or ADMIN role
     * Demonstrates hierarchical role access
     */
    @GetMapping("/user/dashboard")
    @PreAuthorize("hasAnyRole('USER', 'AGENT', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserDashboard(Authentication authentication) {
        log.info("Accessing user dashboard for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to your dashboard");
        response.put("username", authentication.getName());
        response.put("accessLevel", "USER");
        response.put("features", new String[]{"view_profile", "update_profile", "view_bookings"});
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Agent-level endpoint - requires AGENT or ADMIN role
     * Demonstrates role-based access with higher privileges
     */
    @GetMapping("/agent/bookings")
    @PreAuthorize("hasAnyRole('AGENT', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getAgentBookings(Authentication authentication) {
        log.info("Accessing agent bookings for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Agent bookings retrieved successfully");
        response.put("username", authentication.getName());
        response.put("accessLevel", "AGENT");
        response.put("features", new String[]{"view_all_bookings", "manage_customers", "generate_reports"});
        response.put("bookingCount", 150);
        response.put("activeBookings", 45);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Admin-only endpoint - requires ADMIN role
     * Demonstrates strict role-based access control
     */
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    @CustomRequestProcessor(areaRole = {"CONFIG_EDIT"})
    public ResponseEntity<Map<String, Object>> getAdminUsers(Authentication authentication) {
        log.info("Accessing admin users for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin users retrieved successfully");
        response.put("username", authentication.getName());
        response.put("accessLevel", "ADMIN");
        response.put("features", new String[]{"manage_users", "system_config", "view_analytics", "manage_roles"});
        response.put("userCount", 1250);
        response.put("activeUsers", 980);
        response.put("adminUsers", 15);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Scope-based endpoint - requires specific OAuth2 scope
     * Demonstrates fine-grained permission control using scopes
     */
    @GetMapping("/secure/data")
    @PreAuthorize("hasAuthority('SCOPE_read:data')")
    public ResponseEntity<Map<String, Object>> getSecureData(Authentication authentication) {
        log.info("Accessing secure data for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Secure data accessed successfully");
        response.put("username", authentication.getName());
        response.put("requiredScope", "read:data");
        response.put("data", new String[]{"confidential_info_1", "confidential_info_2", "confidential_info_3"});
        response.put("dataCount", 3);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Complex authorization - requires specific role AND scope
     * Demonstrates combining role and scope-based authorization
     */
    @PostMapping("/admin/config")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('SCOPE_write:config')")
    public ResponseEntity<Map<String, Object>> updateSystemConfig(
            @RequestBody Map<String, Object> configData,
            Authentication authentication) {
        log.info("Updating system config by: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "System configuration updated successfully");
        response.put("username", authentication.getName());
        response.put("action", "config_update");
        response.put("timestamp", System.currentTimeMillis());
        response.put("updatedKeys", configData.keySet());
        response.put("requiredRole", "ADMIN");
        response.put("requiredScope", "write:config");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Method-level security with custom business logic
     * Demonstrates using custom security service for complex authorization
     */
    @GetMapping("/secure/sensitive")
    @PreAuthorize("hasRole('ADMIN') or (hasRole('AGENT') and @ssoSecurityService.canAccessSensitiveData(authentication.name))")
    public ResponseEntity<Map<String, Object>> getSensitiveData(Authentication authentication) {
        log.info("Accessing sensitive data for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Sensitive data accessed with custom authorization");
        response.put("username", authentication.getName());
        response.put("accessReason", "Role-based or custom business logic");
        response.put("authorizationMethod", "Custom Security Service");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Business permission endpoint
     * Demonstrates custom business logic authorization
     */
    @GetMapping("/secure/financial-reports")
    @PreAuthorize("@ssoSecurityService.hasBusinessPermission(authentication.name, 'view_financial_reports')")
    @CustomRequestProcessor(areaRole = {"REPORTS_VIEW"})
    public ResponseEntity<Map<String, Object>> getFinancialReports(Authentication authentication) {
        log.info("Accessing financial reports for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Financial reports accessed successfully");
        response.put("username", authentication.getName());
        response.put("permission", "view_financial_reports");
        response.put("reports", new String[]{"monthly_revenue", "quarterly_profit", "annual_summary"});
        
        return ResponseEntity.ok(response);
    }

    /**
     * Token information endpoint (simplified version)
     * Shows basic authentication information without OAuth2 specific details
     */
    @GetMapping("/token/info")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getTokenInfo(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("username", authentication.getName());
        response.put("authenticated", authentication.isAuthenticated());
        response.put("authType", authentication.getClass().getSimpleName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        response.put("principalType", authentication.getPrincipal().getClass().getSimpleName());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Health check endpoint for SSO-protected services
     */
    @GetMapping("/health")
    @PreAuthorize("hasAnyRole('ADMIN', 'AGENT') or hasAuthority('SCOPE_read:health')")
    public ResponseEntity<Map<String, Object>> getHealthStatus(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "SSO Protected Service");
        response.put("timestamp", System.currentTimeMillis());
        response.put("checkedBy", authentication.getName());
        response.put("ssoEnabled", true);
        
        return ResponseEntity.ok(response);
    }
} 
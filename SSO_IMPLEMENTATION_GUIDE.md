# SSO Implementation Guide for TGS Microservices

This guide provides a complete implementation of Single Sign-On (SSO) authorization for Java-based microservices using Spring Boot and OAuth2 Resource Server.

## Overview

The implementation enables JWT-based authentication for microservices that are part of the TGS ecosystem with a centralized Identity Provider (IdP). All microservices act as OAuth2 Resource Servers and validate JWT tokens issued by the IdP.

## 1. Dependencies (build.gradle)

```gradle
dependencies {
    // Existing dependencies...
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    
    // OAuth2 Resource Server for SSO
    implementation 'org.springframework.security:spring-security-oauth2-resource-server'
    implementation 'org.springframework.security:spring-security-oauth2-jose'
}
```

## 2. Configuration Properties (application.properties)

```properties
# OAuth2 Resource Server Configuration for SSO
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://your-idp.example.com/auth/realms/your-realm
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://your-idp.example.com/auth/realms/your-realm/protocol/openid_connect/certs

# SSO Configuration
sso.enabled=true
sso.audience=tgs-microservice
sso.required-authorities=ROLE_USER,ROLE_ADMIN,ROLE_AGENT
```

## 3. Security Configuration (SsoSecurityConfig.java)

```java
package com.tj.services.ums.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SSO Security Configuration for OAuth2 Resource Server
 * This configuration enables JWT-based authentication for microservices
 * that are part of the TGS ecosystem with centralized Identity Provider.
 */
@Configuration
@ConditionalOnProperty(name = "sso.enabled", havingValue = "true")
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Slf4j
@Order(1) // Higher precedence than the existing security config
public class SsoSecurityConfig {

    @Value("${sso.audience:}")
    private String expectedAudience;

    @Value("${sso.required-authorities:}")
    private String requiredAuthorities;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    /**
     * Security filter chain for SSO-enabled endpoints
     */
    @Bean
    @Order(1)
    public SecurityFilterChain ssoSecurityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring SSO Security Filter Chain with Issuer: {}", issuerUri);
        
        http
            .securityMatcher("/api/v1/sso/**", "/api/v1/secure/**") // SSO-protected endpoints
            .authorizeHttpRequests(authz -> authz
                .requestMatchers(HttpMethod.GET, "/api/v1/sso/public/**").permitAll()
                .requestMatchers("/api/v1/sso/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/v1/sso/agent/**").hasAnyRole("AGENT", "ADMIN")
                .requestMatchers("/api/v1/sso/user/**").hasAnyRole("USER", "AGENT", "ADMIN")
                .requestMatchers("/api/v1/secure/**").authenticated()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.disable()); // Configure CORS as needed

        return http.build();
    }

    /**
     * JWT Decoder with custom validation
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("Configuring JWT Decoder with JWK Set URI: {}", jwkSetUri);
        
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
        
        // Add custom validators
        jwtDecoder.setJwtValidator(jwtValidator());
        
        return jwtDecoder;
    }

    /**
     * JWT Validator with audience and issuer validation
     */
    @Bean
    public OAuth2TokenValidator<Jwt> jwtValidator() {
        List<OAuth2TokenValidator<Jwt>> validators = List.of(
            new JwtTimestampValidator(),
            new JwtIssuerValidator(issuerUri),
            audienceValidator()
        );
        
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    /**
     * Custom audience validator
     */
    private OAuth2TokenValidator<Jwt> audienceValidator() {
        return new JwtClaimValidator<List<String>>("aud", aud -> {
            if (StringUtils.hasText(expectedAudience)) {
                return aud != null && aud.contains(expectedAudience);
            }
            return true; // Skip validation if no audience is configured
        });
    }

    /**
     * JWT Authentication Converter to extract authorities from JWT claims
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        
        // Configure how to extract authorities from JWT
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Extract authorities from multiple sources
            Collection<GrantedAuthority> authorities = authoritiesConverter.convert(jwt);
            
            // Also extract from 'authorities' claim if present
            Collection<GrantedAuthority> scopeAuthorities = extractAuthoritiesFromClaim(jwt, "authorities");
            
            // Also extract from 'scope' claim (standard OAuth2)
            Collection<GrantedAuthority> oauthScopes = extractScopeAuthorities(jwt);
            
            // Combine all authorities
            return Stream.of(authorities, scopeAuthorities, oauthScopes)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
        });

        return authenticationConverter;
    }

    /**
     * Extract authorities from a custom claim
     */
    private Collection<GrantedAuthority> extractAuthoritiesFromClaim(Jwt jwt, String claimName) {
        Object authorities = jwt.getClaim(claimName);
        if (authorities instanceof List<?> authList) {
            return authList.stream()
                .map(Object::toString)
                .map(authority -> authority.startsWith("ROLE_") ? authority : "ROLE_" + authority)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        }
        return List.of();
    }

    /**
     * Extract scope-based authorities (standard OAuth2 scopes)
     */
    private Collection<GrantedAuthority> extractScopeAuthorities(Jwt jwt) {
        String scopes = jwt.getClaimAsString("scope");
        if (StringUtils.hasText(scopes)) {
            return Stream.of(scopes.split(" "))
                .map(scope -> "SCOPE_" + scope)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        }
        return List.of();
    }
}
```

## 4. Secured Controller Example (SsoSecuredController.java)

```java
package com.tj.services.ums.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Example secured REST controller demonstrating SSO integration
 * with role-based access control using JWT tokens from Identity Provider.
 */
@RestController
@RequestMapping("/api/v1/sso")
@RequiredArgsConstructor
@Slf4j
public class SsoSecuredController {

    /**
     * Public endpoint - no authentication required
     */
    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> getPublicInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("service", "TGS Microservice");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Authenticated endpoint - requires valid JWT token
     */
    @GetMapping("/secure/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getUserProfile(Authentication authentication) {
        log.info("Accessing user profile for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User profile accessed successfully");
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        
        // Extract JWT claims if available
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            response.put("subject", jwt.getSubject());
            response.put("issuer", jwt.getIssuer());
            response.put("tokenId", jwt.getId());
            response.put("email", jwt.getClaimAsString("email"));
            response.put("preferredUsername", jwt.getClaimAsString("preferred_username"));
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * User-level endpoint - requires USER, AGENT, or ADMIN role
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
        
        return ResponseEntity.ok(response);
    }

    /**
     * Agent-level endpoint - requires AGENT or ADMIN role
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
        
        return ResponseEntity.ok(response);
    }

    /**
     * Admin-only endpoint - requires ADMIN role
     */
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminUsers(Authentication authentication) {
        log.info("Accessing admin users for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin users retrieved successfully");
        response.put("username", authentication.getName());
        response.put("accessLevel", "ADMIN");
        response.put("features", new String[]{"manage_users", "system_config", "view_analytics", "manage_roles"});
        response.put("userCount", 1250);
        response.put("activeUsers", 980);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Scope-based endpoint - requires specific OAuth2 scope
     */
    @GetMapping("/secure/data")
    @PreAuthorize("hasAuthority('SCOPE_read:data')")
    public ResponseEntity<Map<String, Object>> getSecureData(Authentication authentication) {
        log.info("Accessing secure data for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Secure data accessed successfully");
        response.put("username", authentication.getName());
        response.put("scope", "read:data");
        response.put("data", new String[]{"confidential_info_1", "confidential_info_2", "confidential_info_3"});
        
        return ResponseEntity.ok(response);
    }

    /**
     * Complex authorization - requires specific role AND scope
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
        
        return ResponseEntity.ok(response);
    }

    /**
     * Method-level security with custom expression
     */
    @GetMapping("/secure/sensitive")
    @PreAuthorize("hasRole('ADMIN') or (hasRole('AGENT') and @ssoSecurityService.canAccessSensitiveData(authentication.name))")
    public ResponseEntity<Map<String, Object>> getSensitiveData(Authentication authentication) {
        log.info("Accessing sensitive data for: {}", authentication.getName());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Sensitive data accessed with custom authorization");
        response.put("username", authentication.getName());
        response.put("accessReason", "Role-based or custom business logic");
        
        return ResponseEntity.ok(response);
    }
}
```

## 5. Custom Security Service (SsoSecurityService.java)

```java
package com.tj.services.ums.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Custom security service for business logic in SSO authorization
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SsoSecurityService {

    /**
     * Custom business logic to determine if a user can access sensitive data
     * This is used in @PreAuthorize expressions
     */
    public boolean canAccessSensitiveData(String username) {
        log.debug("Checking sensitive data access for user: {}", username);
        
        // Custom business logic - replace with actual implementation
        // For example: check user's department, clearance level, etc.
        
        // Mock implementation - in real scenario, this would query database
        // or external service to determine access rights
        return username != null && 
               !username.toLowerCase().contains("guest") &&
               !username.toLowerCase().contains("temp");
    }

    /**
     * Check if user has specific business permission
     */
    public boolean hasBusinessPermission(String username, String permission) {
        log.debug("Checking business permission '{}' for user: {}", permission, username);
        
        // Mock implementation - replace with actual business logic
        switch (permission.toLowerCase()) {
            case "view_financial_reports":
                return username.endsWith("@finance.company.com");
            case "manage_bookings":
                return username.contains("agent") || username.contains("admin");
            case "system_maintenance":
                return username.contains("admin") || username.contains("sysadmin");
            default:
                return false;
        }
    }
}
```

## 6. JWT Token Structure

Your IdP should issue JWT tokens with the following structure:

```json
{
  "sub": "user123",
  "iss": "https://your-idp.example.com/auth/realms/your-realm",
  "aud": ["tgs-microservice"],
  "exp": 1640995200,
  "iat": 1640991600,
  "email": "user@example.com",
  "preferred_username": "john.doe",
  "roles": ["USER", "AGENT"],
  "authorities": ["read:profile", "write:bookings"],
  "scope": "openid profile email read:data write:config"
}
```

## 7. Authorization Patterns

### Role-Based Access Control (RBAC)
```java
@PreAuthorize("hasRole('ADMIN')")
@PreAuthorize("hasAnyRole('USER', 'AGENT', 'ADMIN')")
```

### Scope-Based Access Control
```java
@PreAuthorize("hasAuthority('SCOPE_read:data')")
@PreAuthorize("hasAuthority('SCOPE_write:config')")
```

### Combined Authorization
```java
@PreAuthorize("hasRole('ADMIN') and hasAuthority('SCOPE_write:config')")
```

### Custom Business Logic
```java
@PreAuthorize("@ssoSecurityService.canAccessSensitiveData(authentication.name)")
```

## 8. Testing SSO Endpoints

### Public Endpoint (No Authentication)
```bash
curl -X GET http://localhost:8085/api/v1/sso/public/info
```

### Authenticated Endpoint (JWT Required)
```bash
curl -X GET http://localhost:8085/api/v1/sso/secure/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Role-Based Endpoint
```bash
curl -X GET http://localhost:8085/api/v1/sso/admin/users \
  -H "Authorization: Bearer YOUR_ADMIN_JWT_TOKEN"
```

## 9. Configuration for Different Environments

### Development (application-dev.properties)
```properties
sso.enabled=false
# Use existing authentication for development
```

### Production (application-prod.properties)
```properties
sso.enabled=true
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://prod-idp.company.com/auth/realms/tgs
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://prod-idp.company.com/auth/realms/tgs/protocol/openid_connect/certs
sso.audience=tgs-production
```

## 10. Error Handling

The SSO implementation automatically handles:
- Invalid JWT tokens (401 Unauthorized)
- Expired tokens (401 Unauthorized)
- Missing required roles (403 Forbidden)
- Missing required scopes (403 Forbidden)

Custom error responses follow the existing error format in your application.

## 11. Monitoring and Logging

The implementation includes comprehensive logging:
- JWT validation events
- Authorization decisions
- Custom security service calls
- Token information extraction

Monitor these logs for security events and troubleshooting.

---

This implementation provides a complete, production-ready SSO solution that integrates seamlessly with your existing UMS architecture while maintaining backward compatibility. 
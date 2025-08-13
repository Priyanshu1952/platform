package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.time.LocalDateTime;

/**
 * DTO for audit log requests
 */
public record AuditLogRequest(
    @NotNull(message = "User ID is required")
    String userId,
    
    @Pattern(regexp = "^(LOGIN|LOGOUT|UPDATE|CREATE|DELETE|VERIFY|SECURITY|ADMIN)$", 
             message = "Action type must be one of: LOGIN, LOGOUT, UPDATE, CREATE, DELETE, VERIFY, SECURITY, ADMIN")
    String actionType,
    
    String description,
    
    String ipAddress,
    
    String userAgent,
    
    LocalDateTime startDate,
    
    LocalDateTime endDate,
    
    @Pattern(regexp = "^(ASC|DESC)$", message = "Sort order must be ASC or DESC")
    String sortOrder,
    
    Integer page,
    
    Integer size
) {} 
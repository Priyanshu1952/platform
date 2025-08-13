package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for creating and updating area roles.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AreaRoleRequest {
    
    @NotBlank(message = "Role code is required")
    @Size(min = 2, max = 50, message = "Role code must be between 2 and 50 characters")
    private String roleCode;
    
    @NotBlank(message = "Role name is required")
    @Size(min = 2, max = 100, message = "Role name must be between 2 and 100 characters")
    private String roleName;
    
    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;
    
    @NotBlank(message = "Functional area is required")
    @Size(min = 2, max = 100, message = "Functional area must be between 2 and 100 characters")
    private String functionalArea;
    
    // Server-managed fields are NOT included:
    // - id (auto-generated)
    // - createdOn (auto-set)
    // - active (default true)
} 
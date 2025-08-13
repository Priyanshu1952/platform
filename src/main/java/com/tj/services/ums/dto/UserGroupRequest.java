package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for creating and updating user groups.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserGroupRequest {
    
    @NotBlank(message = "Group name is required")
    @Size(min = 2, max = 100, message = "Group name must be between 2 and 100 characters")
    private String groupName;
    
    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;
    
    // List of area role codes to assign to this group
    private List<String> areaRoleCodes;
    
    // List of user IDs to add as members
    private List<String> memberUserIds;
    
    // Server-managed fields are NOT included:
    // - id (auto-generated)
    // - createdOn (auto-set)
    // - active (default true)
    // - createdBy (set from authentication context)
} 
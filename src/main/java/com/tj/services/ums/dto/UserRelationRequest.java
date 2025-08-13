package com.tj.services.ums.dto;

import com.tj.services.ums.model.RelationshipType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for creating and updating user relations.
 * Excludes server-managed fields that are annotated with @ForbidInAPIRequest.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRelationRequest {
    
    @NotBlank(message = "User ID 1 is required")
    private String userId1;
    
    @NotBlank(message = "User ID 2 is required")
    private String userId2;
    
    @NotNull(message = "Relationship type is required")
    private RelationshipType relationshipType;
    
    // Priority is client-provided with default value
    @Builder.Default
    private Integer priority = 0;
    
    // Notes are optional
    private String notes;
    
    // Server-managed fields are NOT included:
    // - id (auto-generated)
    // - depth (server-calculated)
    // - userName1, userName2 (denormalized)
    // - createdOn (auto-set)
    // - processedOn (server-managed)
    // - active (default true)
    // - createdBy (set from authentication context)
} 
package com.tj.services.ums.controller;

import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.model.RelationshipType;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserRelationship;
import com.tj.services.ums.repository.UserRelationshipRepository;
import com.tj.services.ums.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for managing user relationships.
 * Provides endpoints for creating, viewing, and managing user-to-user relationships.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/user-relationships")
@RequiredArgsConstructor
@Tag(name = "User Relationships", description = "Endpoints for managing user relationships")
@SecurityRequirement(name = "bearerAuth")
public class UserRelationshipController {
    
    private final UserService userService;
    private final UserRelationshipRepository userRelationshipRepository;
    
    @GetMapping("/allowed-users/{userId}")
    @Operation(summary = "Get allowed user IDs", description = "Get list of user IDs that the given user can interact with")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER') or #userId == authentication.principal.username")
    public ResponseEntity<ApiResponse> getAllowedUserIds(@PathVariable String userId) {
        try {
            List<String> allowedUserIds = userService.getAllowedUserIds(userId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(allowedUserIds)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting allowed user IDs for user: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error retrieving allowed user IDs: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(response);
        }
    }
    
    @PostMapping("/create")
    @Operation(summary = "Create user relationship", description = "Create a new relationship between two users")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<ApiResponse> createRelationship(
            @RequestParam String userId1,
            @RequestParam String userId2,
            @RequestParam RelationshipType relationshipType,
            @RequestParam(required = false) String notes) {
        
        try {
            // Check if users exist
            User user1 = userService.getUserByUserId(userId1);
            User user2 = userService.getUserByUserId(userId2);
            if (user1 == null || user2 == null) {
                throw new IllegalArgumentException("One or both users not found");
            }
            
            // Create relationship
            UserRelationship relationship = new UserRelationship();
            relationship.setUserId1(userId1);
            relationship.setUserId2(userId2);
            relationship.setRelationshipType(relationshipType);
            relationship.setNotes(notes);
            relationship.setActive(true);
            
            userRelationshipRepository.save(relationship);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(201)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(relationship)
                    .build();
            
            return ResponseEntity.status(201).body(response);
        } catch (Exception e) {
            log.error("Error creating relationship between users {} and {}", userId1, userId2, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error creating relationship: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    @GetMapping("/user/{userId}")
    @Operation(summary = "Get user relationships", description = "Get all relationships for a specific user")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER') or #userId == authentication.principal.username")
    public ResponseEntity<ApiResponse> getUserRelationships(@PathVariable String userId) {
        try {
            List<UserRelationship> relationships = userRelationshipRepository.findByUserId(userId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(relationships)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting relationships for user: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error retrieving relationships: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(response);
        }
    }
    
    @GetMapping("/user/{userId}/related-users")
    @Operation(summary = "Get related users", description = "Get all users related to a specific user")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER') or #userId == authentication.principal.username")
    public ResponseEntity<ApiResponse> getRelatedUsers(@PathVariable String userId) {
        try {
            List<User> relatedUsers = userService.getUserRelations(userId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(relatedUsers)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting related users for user: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error retrieving related users: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(response);
        }
    }
    
    @DeleteMapping("/{relationshipId}")
    @Operation(summary = "Delete relationship", description = "Deactivate a user relationship")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<ApiResponse> deleteRelationship(@PathVariable Long relationshipId) {
        try {
            UserRelationship relationship = userRelationshipRepository.findById(relationshipId)
                    .orElseThrow(() -> new IllegalArgumentException("Relationship not found"));
            
            relationship.deactivate();
            userRelationshipRepository.save(relationship);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("Relationship deactivated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error deleting relationship: {}", relationshipId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error deleting relationship: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    @GetMapping("/types")
    @Operation(summary = "Get relationship types", description = "Get all available relationship types")
    public ResponseEntity<ApiResponse> getRelationshipTypes() {
        try {
            RelationshipType[] types = RelationshipType.values();
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(types)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting relationship types", e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error retrieving relationship types: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(response);
        }
    }
} 
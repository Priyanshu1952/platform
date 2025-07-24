package com.tj.services.ums.controller;

import com.tj.services.ums.dto.UserProfileUpdateRequest;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.service.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/profile")
@RequiredArgsConstructor
@Tag(name = "User Profile", description = "Endpoints for managing user profiles")
@SecurityRequirement(name = "bearerAuth")
public class UserProfileController {

    private final UserProfileService userProfileService;

    @GetMapping("/{userId}")
    @Operation(summary = "Get user profile by ID", description = "Retrieve user profile information by user ID")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<AuthUser> getUserProfile(@PathVariable UUID userId) {
        AuthUser user = userProfileService.getUserProfile(userId);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/{userId}")
    @Operation(summary = "Update user profile by ID", description = "Update user profile information by user ID")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<AuthUser> updateUserProfile(@PathVariable UUID userId, @RequestBody UserProfileUpdateRequest request) {
        AuthUser updatedUser = userProfileService.updateUserProfile(userId, request);
        return ResponseEntity.ok(updatedUser);
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user profile", description = "Retrieve profile information for the authenticated user")
    public ResponseEntity<AuthUser> getCurrentUserProfile(@AuthenticationPrincipal AuthUser currentUser) {
        return ResponseEntity.ok(currentUser);
    }

    @PutMapping("/me")
    @Operation(summary = "Update current user profile", description = "Update profile information for the authenticated user")
    public ResponseEntity<AuthUser> updateCurrentUserProfile(@AuthenticationPrincipal AuthUser currentUser, @RequestBody UserProfileUpdateRequest request) {
        AuthUser updatedUser = userProfileService.updateUserProfile(currentUser.getId(), request);
        return ResponseEntity.ok(updatedUser);
    }
}

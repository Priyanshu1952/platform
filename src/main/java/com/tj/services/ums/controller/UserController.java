package com.tj.services.ums.controller;

import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.dto.UserUpdateRequest;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.User;
import com.tj.services.ums.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.Map;

/**
 * Comprehensive controller for user management operations
 * Provides endpoints for updating user information across both AuthUser and User models
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "Endpoints for comprehensive user management")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    // ==================== GET USER INFORMATION ====================

    @GetMapping("/{userId}")
    @Operation(summary = "Get user by ID", description = "Retrieve complete user information by user ID")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> getUserById(@PathVariable String userId) {
        try {
            User user = userService.getUserByUserId(userId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(user)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting user by ID: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(404)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("404")
                    .message("User not found: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(404).body(response);
        }
    }

    @GetMapping("/auth/{authUserId}")
    @Operation(summary = "Get auth user by ID", description = "Retrieve authentication user information by auth user ID")
    @PreAuthorize("hasRole('ADMIN') or #authUserId == authentication.principal.id")
    public ResponseEntity<ApiResponse> getAuthUserById(@PathVariable UUID authUserId) {
        try {
            AuthUser authUser = userService.getAuthUserById(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(authUser)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting auth user by ID: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(404)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("404")
                    .message("Auth user not found: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(404).body(response);
        }
    }

    // ==================== UPDATE USER INFORMATION ====================

    @PutMapping("/{userId}")
    @Operation(summary = "Update user by ID", description = "Update complete user information by user ID")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateUser(@PathVariable String userId, 
                                                 @Valid @RequestBody UserUpdateRequest request) {
        try {
            User updatedUser = userService.updateUserByUserId(userId, request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(updatedUser)
                    .message("User updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PutMapping("/auth/{authUserId}")
    @Operation(summary = "Update auth user by ID", description = "Update authentication user information by auth user ID")
    @PreAuthorize("hasRole('ADMIN') or #authUserId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateAuthUser(@PathVariable UUID authUserId, 
                                                     @Valid @RequestBody UserUpdateRequest request) {
        try {
            AuthUser updatedAuthUser = userService.updateAuthUser(authUserId, request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(updatedAuthUser)
                    .message("Auth user updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating auth user: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating auth user: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== PARTIAL UPDATES ====================

    @PatchMapping("/{userId}/profile")
    @Operation(summary = "Update user profile", description = "Update user profile information")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateUserProfile(@PathVariable String userId, 
                                                        @Valid @RequestBody UserUpdateRequest request) {
        try {
            // Convert userId to UUID for auth user operations
            User user = userService.getUserByUserId(userId);
            Optional<AuthUser> authUserOpt = userService.getAuthUserByEmail(user.getEmail());
            
            if (authUserOpt.isPresent()) {
                userService.updateUserProfile(authUserOpt.get().getId(), request);
            }
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User profile updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user profile: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user profile: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PatchMapping("/{userId}/address")
    @Operation(summary = "Update user address", description = "Update user address information")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateUserAddress(@PathVariable String userId, 
                                                        @Valid @RequestBody UserUpdateRequest request) {
        try {
            User user = userService.getUserByUserId(userId);
            Optional<AuthUser> authUserOpt = userService.getAuthUserByEmail(user.getEmail());
            
            if (authUserOpt.isPresent()) {
                userService.updateUserAddress(authUserOpt.get().getId(), request);
            }
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User address updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user address: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user address: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PatchMapping("/{userId}/contact")
    @Operation(summary = "Update user contact info", description = "Update user contact information")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateUserContactInfo(@PathVariable String userId, 
                                                            @Valid @RequestBody UserUpdateRequest request) {
        try {
            User user = userService.getUserByUserId(userId);
            Optional<AuthUser> authUserOpt = userService.getAuthUserByEmail(user.getEmail());
            
            if (authUserOpt.isPresent()) {
                userService.updateUserContactInfo(authUserOpt.get().getId(), request);
            }
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User contact info updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user contact info: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user contact info: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PatchMapping("/{userId}/kyc")
    @Operation(summary = "Update user KYC info", description = "Update user KYC information")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateUserKYCInfo(@PathVariable String userId, 
                                                        @Valid @RequestBody UserUpdateRequest request) {
        try {
            User user = userService.getUserByUserId(userId);
            Optional<AuthUser> authUserOpt = userService.getAuthUserByEmail(user.getEmail());
            
            if (authUserOpt.isPresent()) {
                userService.updateUserKYCInfo(authUserOpt.get().getId(), request);
            }
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User KYC info updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user KYC info: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user KYC info: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PatchMapping("/auth/{authUserId}/security")
    @Operation(summary = "Update auth user security", description = "Update authentication user security settings")
    @PreAuthorize("hasRole('ADMIN') or #authUserId == authentication.principal.id")
    public ResponseEntity<ApiResponse> updateAuthUserSecurity(@PathVariable UUID authUserId, 
                                                             @Valid @RequestBody UserUpdateRequest request) {
        try {
            AuthUser updatedAuthUser = userService.updateAuthUserSecurity(authUserId, request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(updatedAuthUser)
                    .message("Auth user security updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating auth user security: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating auth user security: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== VERIFICATION OPERATIONS ====================

    @PostMapping("/auth/{authUserId}/verify/email")
    @Operation(summary = "Mark email verified", description = "Mark user email as verified")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> markEmailVerified(@PathVariable UUID authUserId) {
        try {
            userService.markEmailVerified(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("Email marked as verified successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error marking email verified: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error marking email verified: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/auth/{authUserId}/verify/pan")
    @Operation(summary = "Mark PAN verified", description = "Mark user PAN as verified")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> markPanVerified(@PathVariable UUID authUserId) {
        try {
            userService.markPanVerified(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("PAN marked as verified successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error marking PAN verified: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error marking PAN verified: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/auth/{authUserId}/verify/aadhaar")
    @Operation(summary = "Mark Aadhaar verified", description = "Mark user Aadhaar as verified")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> markAadhaarVerified(@PathVariable UUID authUserId) {
        try {
            userService.markAadhaarVerified(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("Aadhaar marked as verified successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error marking Aadhaar verified: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error marking Aadhaar verified: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== SECURITY OPERATIONS ====================

    @PostMapping("/auth/{authUserId}/lock")
    @Operation(summary = "Lock user account", description = "Lock user account for security")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> lockUserAccount(@PathVariable UUID authUserId) {
        try {
            userService.lockUserAccount(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User account locked successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error locking user account: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error locking user account: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/auth/{authUserId}/unlock")
    @Operation(summary = "Unlock user account", description = "Unlock user account")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> unlockUserAccount(@PathVariable UUID authUserId) {
        try {
            userService.unlockUserAccount(authUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User account unlocked successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error unlocking user account: {}", authUserId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error unlocking user account: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== FINANCIAL OPERATIONS ====================

    @PatchMapping("/{userId}/balance")
    @Operation(summary = "Update user balance", description = "Update user balance")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> updateUserBalance(@PathVariable String userId, 
                                                        @RequestParam Double newBalance) {
        try {
            User user = userService.getUserByUserId(userId);
            userService.updateUserBalance(user.getId(), newBalance);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User balance updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user balance: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user balance: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PatchMapping("/{userId}/wallet-balance")
    @Operation(summary = "Update user wallet balance", description = "Update user wallet balance")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> updateUserWalletBalance(@PathVariable String userId, 
                                                              @RequestParam Double newWalletBalance) {
        try {
            User user = userService.getUserByUserId(userId);
            userService.updateUserWalletBalance(user.getId(), newWalletBalance);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("User wallet balance updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating user wallet balance: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating user wallet balance: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== BULK OPERATIONS ====================

    @PutMapping("/bulk/update")
    @Operation(summary = "Update multiple users", description = "Update multiple users with the same data")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> updateMultipleUsers(@RequestParam List<Long> userIds, 
                                                          @Valid @RequestBody UserUpdateRequest request) {
        try {
            List<User> updatedUsers = userService.updateMultipleUsers(userIds, request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(updatedUsers)
                    .message("Multiple users updated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error updating multiple users: {}", userIds, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error updating multiple users: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/bulk/activate")
    @Operation(summary = "Activate multiple users", description = "Activate multiple users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> activateMultipleUsers(@RequestParam List<Long> userIds) {
        try {
            userService.activateUsers(userIds);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("Multiple users activated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error activating multiple users: {}", userIds, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error activating multiple users: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/bulk/deactivate")
    @Operation(summary = "Deactivate multiple users", description = "Deactivate multiple users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deactivateMultipleUsers(@RequestParam List<Long> userIds) {
        try {
            userService.deactivateUsers(userIds);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .message("Multiple users deactivated successfully")
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error deactivating multiple users: {}", userIds, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error deactivating multiple users: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== SEARCH AND QUERY OPERATIONS ====================

    @GetMapping("/search")
    @Operation(summary = "Search users", description = "Search users by name or email")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> searchUsers(@RequestParam String query) {
        try {
            List<User> users = userService.searchUsers(query);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(users)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error searching users: {}", query, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error searching users: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/by-role/{role}")
    @Operation(summary = "Get users by role", description = "Get all users with a specific role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getUsersByRole(@PathVariable String role) {
        try {
            List<User> users = userService.getUsersByRole(role);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(users)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting users by role: {}", role, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error getting users by role: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/by-status/{status}")
    @Operation(summary = "Get users by status", description = "Get all users with a specific status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getUsersByStatus(@PathVariable String status) {
        try {
            List<User> users = userService.getUsersByStatus(status);
            
            ApiResponse.Status status_obj = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status_obj)
                    .data(users)
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting users by status: {}", status, e);
            
            ApiResponse.Status status_obj = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error getting users by status: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status_obj)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ==================== VALIDATION OPERATIONS ====================

    @GetMapping("/validate/email")
    @Operation(summary = "Check email availability", description = "Check if email is available")
    public ResponseEntity<ApiResponse> checkEmailAvailability(@RequestParam String email, 
                                                             @RequestParam(required = false) UUID excludeUserId) {
        try {
            boolean isAvailable = userService.isEmailAvailable(email, excludeUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(Map.of("available", isAvailable))
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error checking email availability: {}", email, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error checking email availability: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/validate/mobile")
    @Operation(summary = "Check mobile availability", description = "Check if mobile number is available")
    public ResponseEntity<ApiResponse> checkMobileAvailability(@RequestParam String mobile, 
                                                              @RequestParam(required = false) UUID excludeUserId) {
        try {
            boolean isAvailable = userService.isMobileAvailable(mobile, excludeUserId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(Map.of("available", isAvailable))
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error checking mobile availability: {}", mobile, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error checking mobile availability: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/validate/user-id")
    @Operation(summary = "Check user ID availability", description = "Check if user ID is available")
    public ResponseEntity<ApiResponse> checkUserIdAvailability(@RequestParam String userId) {
        try {
            boolean isAvailable = userService.isUserIdAvailable(userId);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .data(Map.of("available", isAvailable))
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error checking user ID availability: {}", userId, e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(400)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("400")
                    .message("Error checking user ID availability: " + e.getMessage())
                    .build();
            
            ApiResponse response = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.badRequest().body(response);
        }
    }
} 
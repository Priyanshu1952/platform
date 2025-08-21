package com.tj.services.ums.controller;

import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.dto.EmulationRequest;
import com.tj.services.ums.dto.EmulationResponse;
import com.tj.services.ums.dto.EmulationSessionResponse;
import com.tj.services.ums.exception.EmulationException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.EmulationSession;
import com.tj.services.ums.model.User;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.EmulationService;
import com.tj.services.ums.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
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

@RestController
@RequestMapping("/api/v1/users")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "User Emulation", description = "User emulation management APIs")
@RequiredArgsConstructor
@Slf4j
public class EmulationController {
    
    private final EmulationService emulationService;
    private final UserService userService;
    private final AuthUserRepository authUserRepository;
    private final UserRepository userRepository;
    
    @PostMapping("/emulate/{targetUserId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Emulate user", description = "Start emulating a linked user")
    public ResponseEntity<EmulationResponse> emulateUser(
            @PathVariable String targetUserId,
            @RequestBody @Valid EmulationRequest request,
            @AuthenticationPrincipal AuthUser currentUser,
            HttpServletRequest httpRequest) {
        
        try {
            // Get the target user by userId
            User targetUser = userService.getUserByUserId(targetUserId);
            if (targetUser == null) {
                throw new EmulationException("Target user not found");
            }
            
            // Validate that the target user is linked to the current user
            if (!emulationService.canEmulateUser(currentUser.getId(), UUID.fromString(targetUser.getId().toString()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(EmulationResponse.builder()
                                .success(false)
                                .message("Target user is not linked to your account")
                                .build());
            }
            
            // Start emulation session
            EmulationSession session = emulationService.startEmulation(
                    currentUser.getId(),
                    UUID.fromString(targetUser.getId().toString()),
                    request.getReason(),
                    getClientIpAddress(httpRequest)
            );
            
            // Generate emulated access token
            String emulatedAccessToken = emulationService.generateEmulatedAccessToken(targetUser, currentUser.getId());
            
            // Return response with emulated token
            EmulationResponse response = EmulationResponse.builder()
                    .success(true)
                    .message("User emulation started successfully")
                    .emulatedAccessToken(emulatedAccessToken)
                    .targetUser(targetUser)
                    .sessionId(session.getId())
                    .build();
            
            return ResponseEntity.ok(response);
            
        } catch (EmulationException e) {
            return ResponseEntity.badRequest()
                    .body(EmulationResponse.builder()
                            .success(false)
                            .message(e.getMessage())
                            .build());
        } catch (Exception e) {
            log.error("Error during user emulation", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(EmulationResponse.builder()
                            .success(false)
                            .message("Internal server error during emulation")
                            .build());
        }
    }
    
    @PostMapping("/emulation/{sessionId}/end")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "End emulation", description = "End an active emulation session")
    public ResponseEntity<ApiResponse> endEmulation(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal AuthUser currentUser) {
        
        try {
            emulationService.endEmulation(sessionId, currentUser.getId());
            
            return ResponseEntity.ok(ApiResponse.builder()
                    .status(ApiResponse.Status.builder().success(true).httpStatus(200).build())
                    .message("Emulation session ended successfully")
                    .build());
        } catch (EmulationException e) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.builder()
                            .status(ApiResponse.Status.builder().success(false).httpStatus(400).build())
                            .message(e.getMessage())
                            .build());
        }
    }
    
    @GetMapping("/emulation/linked-users")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get linked users", description = "Get list of users that can be emulated")
    public ResponseEntity<List<User>> getLinkedUsers(@AuthenticationPrincipal AuthUser currentUser) {
        try {
            List<User> linkedUsers = emulationService.getLinkedUsers(currentUser.getId());
            return ResponseEntity.ok(linkedUsers);
        } catch (Exception e) {
            log.error("Error getting linked users", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    @GetMapping("/emulation/sessions/active")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get active emulation sessions", description = "Get active emulation sessions for current user")
    public ResponseEntity<List<EmulationSessionResponse>> getActiveSessions(@AuthenticationPrincipal AuthUser currentUser) {
        try {
            EmulationSession activeSession = emulationService.getActiveSession(currentUser.getId());
            if (activeSession != null) {
                return ResponseEntity.ok(List.of(EmulationSessionResponse.from(activeSession)));
            }
            return ResponseEntity.ok(List.of());
        } catch (Exception e) {
            log.error("Error getting active sessions", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0];
        }
        return request.getRemoteAddr();
    }
} 
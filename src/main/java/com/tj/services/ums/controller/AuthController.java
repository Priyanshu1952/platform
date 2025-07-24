package com.tj.services.ums.controller;

import com.tj.services.ums.config.RateLimiter;
import com.tj.services.ums.communicator.impl.RealOtpCommunicator;
import com.tj.services.ums.dto.*;
import com.tj.services.ums.service.AuthService;
import com.tj.services.ums.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints for user authentication and registration")
public class AuthController {

    private final AuthService authService;
    private final RealOtpCommunicator otpCommunicator;
    private final PasswordResetService passwordResetService;
    
    private final RateLimiter rateLimiter;

    @PostMapping("/login")
    @Operation(summary = "Standard login", description = "Authenticate using email and password")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        LoginResponse response = authService.login(request, httpRequest);
        return ResponseEntity.ok()
                .header("X-Auth-Method", "password")
                .body(response);
    }

    @PostMapping("/otp/login")
    @Operation(summary = "OTP login", description = "Authenticate using mobile OTP")
    public ResponseEntity<OtpLoginResponse> otpLogin(
            @Valid @RequestBody OtpLoginRequest request,
            HttpServletRequest httpRequest) {
        OtpLoginResponse response = authService.otpLogin(request, httpRequest);
        return ResponseEntity.ok()
                .header("X-Auth-Method", "otp")
                .body(response);
    }

    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Register a new user account")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        if (rateLimiter.isBlocked(httpRequest.getRemoteAddr())) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
        }
        RegisterResponse response = authService.register(request, httpRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .header("X-Account-Status", "pending_verification")
                .body(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh token",
            description = "Obtain new access token using refresh token",
            security = @SecurityRequirement(name = "refreshTokenAuth"))
    public ResponseEntity<TokenRefreshResponse> refreshToken(
            @Valid @RequestBody TokenRefreshRequest request) {
        TokenRefreshResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout",
            description = "Invalidate current session",
            security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/test-sms")
    public ResponseEntity<String> testSms() {
        boolean success = otpCommunicator.sendOtp("+917728049119", "123456");
        return ResponseEntity.ok(success ? "Sent" : "Failed");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Admin endpoint", description = "An endpoint only accessible to admins")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Welcome, Admin!");
    }

    @PostMapping("/password/reset-request")
    @Operation(summary = "Request password reset", description = "Sends a password reset token to the user's email")
    public ResponseEntity<Void> requestPasswordReset(@Valid @RequestBody PasswordResetTokenRequest request) {
        passwordResetService.createPasswordResetToken(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Reset password", description = "Resets the user's password using a valid token")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify email", description = "Verifies user email with a token")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        
        return ResponseEntity.ok("Email verified successfully!");
    }
}

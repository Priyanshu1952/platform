package com.tj.services.ums.controller;

import com.tj.services.ums.config.RateLimiter;
import com.tj.services.ums.communicator.impl.RealOtpCommunicator;
import com.tj.services.ums.dto.*;
import com.tj.services.ums.service.AuthService;
import com.tj.services.ums.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final RealOtpCommunicator otpCommunicator;
    private final PasswordResetService passwordResetService;
    
    private final RateLimiter rateLimiter;

    @PostMapping("/login")
    @Operation(summary = "Standard login", description = "Authenticate using email and password")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        
        // Check rate limit
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("login_" + clientIp)) {
            return ResponseEntity.status(429)
                    .header("X-RateLimit-Limit", "10 requests per minute")
                    .build();
        }
        
        LoginResponse response = authService.login(request, httpRequest);
        return ResponseEntity.ok()
                .header("X-Auth-Method", "password")
                .body(response);
    }

    @PostMapping("/otp/email/request")
@Operation(summary = "Request OTP to email", description = "Send OTP to user's email for login")
public ResponseEntity<SendOtpResponse> requestOtpToEmail(
        @Valid @RequestBody EmailOtpRequest request,
        HttpServletRequest httpRequest) {
    String clientIp = httpRequest.getRemoteAddr();
    if (rateLimiter.isBlocked("otp_email_request_" + clientIp)) {
        return ResponseEntity.status(429).header("X-RateLimit-Limit", "10 requests per minute").build();
    }
    SendOtpResponse response = authService.sendOtpToEmail(request);
    return ResponseEntity.ok(response);
}

@PostMapping("/otp/email/login")
@Operation(summary = "Login with email OTP", description = "Authenticate using email and OTP")
public ResponseEntity<OtpLoginResponse> emailOtpLogin(
        @Valid @RequestBody EmailOtpLoginRequest request,
        HttpServletRequest httpRequest) {
    String clientIp = httpRequest.getRemoteAddr();
    if (rateLimiter.isBlocked("otp_email_login_" + clientIp)) {
        return ResponseEntity.status(429).header("X-RateLimit-Limit", "10 requests per minute").build();
    }
    try {
        OtpLoginResponse response = authService.emailOtpLogin(request, httpRequest);
        return ResponseEntity.ok().header("X-Auth-Method", "otp_email").body(response);
    } catch (Exception e) {
        log.error("Error in /otp/email/login: {}", e.getMessage(), e);
        throw e;
    }
}

@PostMapping("/otp/login")
@Operation(summary = "OTP login", description = "Authenticate using mobile OTP")
public ResponseEntity<OtpLoginResponse> otpLogin(
        @Valid @RequestBody OtpLoginRequest request,
        HttpServletRequest httpRequest) {
        // Check rate limit for OTP login
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("otp_login_" + clientIp)) {
            return ResponseEntity.status(429).header("X-RateLimit-Limit", "10 requests per minute").build();
        }
        
        try {
            OtpLoginResponse response = authService.otpLogin(request, httpRequest);
            return ResponseEntity.ok()
                    .header("X-Auth-Method", "otp")
                    .body(response);
        } catch (Exception e) {
            // Log full stacktrace
            org.slf4j.LoggerFactory.getLogger(AuthController.class).error("Error in /otp/login: {}", e.getMessage(), e);
            // Optionally, expose error in response for development/debugging
            return ResponseEntity.status(500).body(null);
        }
    }

    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Register a new user account")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        // Check rate limit for registration
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("register_" + clientIp)) {
            return ResponseEntity.status(429)
                    .header("X-RateLimit-Limit", "5 requests per hour")
                    .build();
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
    public ResponseEntity<Void> requestPasswordReset(
            @Valid @RequestBody PasswordResetTokenRequest request,
            HttpServletRequest httpRequest) {
        // Check rate limit for password reset requests
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("reset_request_" + clientIp)) {
            return ResponseEntity.status(429)
                    .header("X-RateLimit-Limit", "3 requests per hour")
                    .build();
        }
        
        passwordResetService.createPasswordResetToken(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Reset password", description = "Resets the user's password using a valid token")
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest httpRequest) {
        // Check rate limit for password reset attempts
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("reset_attempt_" + clientIp)) {
            return ResponseEntity.status(429)
                    .header("X-RateLimit-Limit", "5 attempts per hour")
                    .build();
        }
        
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify email", description = "Verifies user email with a token")
    public ResponseEntity<String> verifyEmail(
            @RequestParam("token") String token,
            HttpServletRequest httpRequest) {
        // Check rate limit for email verification attempts
        String clientIp = httpRequest.getRemoteAddr();
        if (rateLimiter.isBlocked("verify_email_" + clientIp)) {
            return ResponseEntity.status(429)
                    .header("X-RateLimit-Limit", "10 attempts per hour")
                    .body("Too many verification attempts. Please try again later.");
        }
        
        boolean isVerified = authService.verifyEmail(token);
        if (isVerified) {
            return ResponseEntity.ok("Email verified successfully!");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid or expired verification token.");
        }
    }
}

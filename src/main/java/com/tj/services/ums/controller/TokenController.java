package com.tj.services.ums.controller;

import com.tj.services.ums.dto.TokenRefreshRequest;
import com.tj.services.ums.dto.TokenRefreshResponse;
import com.tj.services.ums.utils.JwtUtil;
import io.jsonwebtoken.JwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/api/v1/token")
@RequiredArgsConstructor
@Tag(name = "Token Management", description = "Endpoints for token operations")
public class TokenController {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token",
            description = "Generate new access token using valid refresh token",
            security = @SecurityRequirement(name = "refreshTokenAuth"))
    public ResponseEntity<TokenRefreshResponse> refreshToken(
            @RequestBody TokenRefreshRequest request) {

        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
            return buildErrorResponse("Refresh token is required", HttpStatus.BAD_REQUEST);
        }

        String refreshToken = request.refreshToken();

        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            return buildErrorResponse("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        try {
            String username = jwtUtil.extractUsername(refreshToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (!jwtUtil.isTokenValid(refreshToken, userDetails)) {
                return buildErrorResponse("Refresh token is not valid for this user", HttpStatus.FORBIDDEN);
            }

            String newAccessToken = jwtUtil.generateAccessToken(userDetails);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);
            Date expiresAt = jwtUtil.extractExpiration(newAccessToken);

            return ResponseEntity.ok(
                    new TokenRefreshResponse(
                            "Token refreshed successfully",
                            newAccessToken,
                            newRefreshToken,
                            expiresAt
                    )
            );
        } catch (UsernameNotFoundException e) {
            return buildErrorResponse("User not found", HttpStatus.NOT_FOUND);
        } catch (JwtException e) {
            return buildErrorResponse("Invalid JWT token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return buildErrorResponse("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate token",
            description = "Check if a token is valid and not expired")
    public ResponseEntity<Boolean> validateToken(@RequestBody String token) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(false);
        }

        try {
            boolean isValid = !jwtUtil.isTokenExpired(token) &&
                    jwtUtil.extractUsername(token) != null;
            return ResponseEntity.ok(isValid);
        } catch (Exception e) {
            return ResponseEntity.ok(false);
        }
    }

    private ResponseEntity<TokenRefreshResponse> buildErrorResponse(String message, HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new TokenRefreshResponse(
                        message,
                        "",  // empty string instead of null
                        "",  // empty string instead of null
                        null // only expiration date remains null
                ));
    }
}
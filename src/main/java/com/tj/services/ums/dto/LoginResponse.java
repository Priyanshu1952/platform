package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.tj.services.ums.model.AuthUser;

import java.time.Instant;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        boolean twoFactorRequired,  // Indicates if 2FA is needed

        String token,              // JWT access token (null if 2FA required)

        String refreshToken,       // JWT refresh token (null if 2FA required)

        Instant expiresAt,         // Token expiration time (null if 2FA required)

        String otpDeliveryMethod,  // e.g., "SMS", "EMAIL" (present if 2FA required)

        UserInfo userInfo          // Basic user information (optional)
) {
    // Factory method for successful login (with tokens)
    public static LoginResponse success(String token, String refreshToken, Instant expiresAt, AuthUser user) {
        return new LoginResponse(
                false,
                token,
                refreshToken,
                expiresAt,
                null,
                new UserInfo(user.getId(), user.getEmail(), user.getName())
        );
    }

    // Factory method for 2FA required case
    public static LoginResponse twoFactorRequired(String otpDeliveryMethod) {
        return new LoginResponse(
                true,
                null,
                null,
                null,
                otpDeliveryMethod,
                null
        );
    }

    // Basic user information DTO
    public record UserInfo(
            UUID id,
            String email,
            String name
    ) {}
}
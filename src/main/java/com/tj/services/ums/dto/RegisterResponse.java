package com.tj.services.ums.dto;

import com.tj.services.ums.model.AuthUser;

import java.util.UUID;

/**
 * DTO for registration response containing user details
 */
public record RegisterResponse(
        UUID userId,
        String deviceId,
        String name,
        String email,
        String mobile,
        String message
) {
    /**
     * Creates a RegisterResponse from an AuthUser
     * @param user The authenticated user
     * @param deviceId The device ID associated with the registration
     * @return A new RegisterResponse instance
     */
    public static RegisterResponse fromUser(AuthUser user, String deviceId) {
        return new RegisterResponse(
                user.getId(),
                deviceId,
                user.getName(),
                user.getEmail(),
                user.getMobile(),
                "Registration successful"
        );
    }
}

package com.tj.services.ums.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetRequest(
        @Email(message = "Invalid email") String email,
        @NotBlank(message = "Token is required") String token,
        @NotBlank(message = "New password is required") String newPassword
) {}
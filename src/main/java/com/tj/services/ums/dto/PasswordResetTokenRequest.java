package com.tj.services.ums.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetTokenRequest(
        @Email(message = "Invalid email") String email
) {}
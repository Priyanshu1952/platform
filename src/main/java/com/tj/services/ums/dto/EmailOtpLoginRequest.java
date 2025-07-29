package com.tj.services.ums.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailOtpLoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "OTP is required")
        @Size(min = 4, max = 8, message = "OTP must be between 4 and 8 digits")
        String otp,

        @NotBlank(message = "Device ID is required")
        String deviceId
) {}

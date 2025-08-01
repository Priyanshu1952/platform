package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record OtpLoginRequest(
        @NotBlank(message = "Mobile number is required")
        @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid mobile number format")
        String mobile,

        @NotBlank(message = "OTP is required")
        @Size(min = 4, max = 8, message = "OTP must be between 4 and 8 digits")
        String otp,

        @NotBlank(message = "Device ID is required")
        String deviceId
) {}

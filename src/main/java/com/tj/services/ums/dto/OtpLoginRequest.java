package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpLoginRequest(
        @NotBlank(message = "Mobile number must not be blank")
        @Pattern(regexp = "^\\+\\d{10,15}$", message = "Mobile number must be between 10 and 15 digits and may include a leading +")
        String mobile,

        @NotBlank(message = "OTP must not be blank")
        String otp,

        @NotBlank(message = "Device ID must not be blank")
        String deviceId
) {}

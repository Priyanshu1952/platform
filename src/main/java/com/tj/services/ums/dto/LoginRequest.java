package com.tj.services.ums.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password must not be blank")
        String password,

//        @NotBlank(message = "Device ID must not be blank")
        String deviceId
) {}

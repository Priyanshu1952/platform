package com.tj.services.ums.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
        @NotBlank(message = "Name is required") String name,
        @Email(message = "Invalid email") String email,
        @NotBlank(message = "Password is required") String password,
        @NotBlank(message = "Mobile number is required") String mobile
) {}
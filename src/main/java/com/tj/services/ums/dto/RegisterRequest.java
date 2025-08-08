package com.tj.services.ums.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record RegisterRequest(
        @NotBlank(message = "Name is required") String name,
        @Email(message = "Invalid email") String email,
        @NotBlank(message = "Password is required") String password,
        @NotBlank(message = "Mobile number is required") String mobile,
        @Valid @NotNull(message = "Address is required") AddressRequest address,
        @NotBlank(message = "Role is required") 
        @Pattern(regexp = "^(USER|AGENT|ADMIN)$", message = "Role must be one of: USER, AGENT, ADMIN")
        String role
) {}
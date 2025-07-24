package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserProfileUpdateRequest(
        @NotBlank(message = "Name is required") String name,
        @NotBlank(message = "Mobile number is required") String mobile
) {}
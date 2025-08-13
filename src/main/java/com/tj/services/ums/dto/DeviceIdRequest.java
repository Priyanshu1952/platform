package com.tj.services.ums.dto;

import jakarta.validation.constraints.NotNull;

/**
 * DTO for device ID requests
 */
public record DeviceIdRequest(
    @NotNull(message = "User ID is required")
    String userId
) {} 
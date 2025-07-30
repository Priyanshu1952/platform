package com.tj.services.ums.dto;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.UUID;

public record RegisterResponse(
        UUID userId,
        String deviceId,
        String message
) {}

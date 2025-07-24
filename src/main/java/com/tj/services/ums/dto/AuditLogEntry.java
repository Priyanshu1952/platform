package com.tj.services.ums.dto;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record AuditLogEntry(
        String eventType,
        String userId,
        String ipAddress,
        String deviceId,
        LocalDateTime timestamp,
        boolean success,
        String details
) {}
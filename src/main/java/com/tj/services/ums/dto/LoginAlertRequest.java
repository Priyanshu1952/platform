package com.tj.services.ums.dto;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record LoginAlertRequest(
        String userId,
        String email,
        String username,
        String ipAddress,
        String deviceInfo,
        LocalDateTime timestamp,
        String location,
        boolean suspiciousActivity
) {}
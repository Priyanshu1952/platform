package com.tj.services.ums.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for device ID responses
 */
public record DeviceIdResponse(
    String userId,
    List<DeviceInfo> devices
) {
    
    /**
     * Device information
     */
    public record DeviceInfo(
        String deviceId,
        String deviceName,
        String deviceType,
        String ipAddress,
        String userAgent,
        LocalDateTime lastUsed,
        Boolean isActive,
        Boolean isTrusted
    ) {}
} 
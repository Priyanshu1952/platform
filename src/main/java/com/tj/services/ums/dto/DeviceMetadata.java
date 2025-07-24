package com.tj.services.ums.dto;

import lombok.Builder;

@Builder
public record DeviceMetadata(
    String deviceId,
    String deviceName,
    String deviceType, // MOBILE, DESKTOP, TABLET, UNKNOWN
    String osName,
    String osVersion,
    String browserName,
    String browserVersion,
    String ipAddress,
    String location,
    String userAgent,
    boolean isProxy,
    boolean isTorExitNode,
    String screenResolution,
    String timezone,
    String country,
    String region,
    String city
) {}
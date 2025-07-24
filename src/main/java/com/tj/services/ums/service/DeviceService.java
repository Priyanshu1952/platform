package com.tj.services.ums.service;

import com.tj.services.ums.dto.DeviceMetadata;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.DeviceInfo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface DeviceService {
    // Existing methods
    boolean isIpAllowed(List<String> whitelistedIps, String remoteIp);
    DeviceInfo getDeviceInfo(String fullDeviceId);
    void sendOtp(String fullDeviceId, String mobile);

    // New method
    void registerDevice(String fullDeviceId, AuthUser user, Object securityConfiguration, DeviceMetadata metadata);

    @Transactional
    void registerDevice(String fullDeviceId, AuthUser user, Object securityConfiguration,
                        HttpServletRequest request);

    @Transactional(readOnly = true)
    boolean isDeviceTrusted(String fullDeviceId);

    @Transactional
    void updateDeviceTrustStatus(String fullDeviceId, boolean trusted);
}
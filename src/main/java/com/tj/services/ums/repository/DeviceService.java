package com.tj.services.ums.repository;

import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.DeviceInfo;

import java.util.List;

public interface DeviceService {
    // Existing methods
    boolean isIpAllowed(List<String> whitelistedIps, String remoteIp);
    DeviceInfo getDeviceInfo(String fullDeviceId);
    void sendOtp(String fullDeviceId, String mobile);

    // New method
    void registerDevice(String fullDeviceId, AuthUser user, Object securityConfiguration);
}
package com.tj.services.ums.service.impl;

import com.tj.services.ums.helper.DeviceMetadataExtractor;
import com.tj.services.ums.config.SystemSecurityConfig;
import com.tj.services.ums.dto.DeviceMetadata;
import com.tj.services.ums.dto.SendOtpRequest;
import com.tj.services.ums.exception.DeviceNotFoundException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.DeviceInfo;
import com.tj.services.ums.model.GeoLocation;
import com.tj.services.ums.model.OtpType;

import com.tj.services.ums.repository.DeviceInfoRepository;
import com.tj.services.ums.service.DeviceService;
import com.tj.services.ums.service.GeoLocationService;
import com.tj.services.ums.service.OtpService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua_parser.Client;
import ua_parser.Parser;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceServiceImpl implements DeviceService {

    private final DeviceInfoRepository deviceInfoRepository;
    private final Parser uaParser;
    private final GeoLocationService geoLocationService;
    private final SystemSecurityConfig securityConfig;
    private final OtpService otpService;
    private final DeviceMetadataExtractor deviceMetadataExtractor;

    @Override
    @Transactional(readOnly = true)
    public boolean isIpAllowed(List<String> whitelistedIps, String remoteIp) {
        if (!securityConfig.isIpAllowed(remoteIp)) {
            log.warn("IP blocked by system policy: {}", remoteIp);
            return false;
        }

        if (securityConfig.isEnableGeoIpFiltering() &&
                geoLocationService.isBlockedCountry(remoteIp, securityConfig.getBlockedCountries())) {
            log.warn("IP blocked by country policy: {}", remoteIp);
            return false;
        }

        return whitelistedIps == null || whitelistedIps.isEmpty()
                ? securityConfig.isAllowUnlistedIps()
                : whitelistedIps.contains(remoteIp);
    }

    @Override
    @Transactional(readOnly = true)
    public DeviceInfo getDeviceInfo(String fullDeviceId) {
        return deviceInfoRepository.findFirstByFullDeviceIdOrderByLastLoginTimeDesc(fullDeviceId)
                .orElseThrow(() -> new DeviceNotFoundException("Device not found: " + fullDeviceId));
    }

    @Override
    @Transactional
    public void sendOtp(String fullDeviceId, String mobile) {
        DeviceInfo device = getDeviceInfo(fullDeviceId);
        otpService.sendOtp(new SendOtpRequest(fullDeviceId, mobile, device.getUser().getEmail(), OtpType.SMS));
        device.setLastOtpSent(LocalDateTime.now());
        deviceInfoRepository.save(device);
        log.info("OTP sent to device {} for mobile {}", fullDeviceId, mobile);
    }

    @Override
    @Transactional
    public void registerDevice(String fullDeviceId, AuthUser user, Object securityConfiguration,
                               DeviceMetadata metadata) {
        DeviceInfo deviceInfo = deviceInfoRepository.findByFullDeviceId(fullDeviceId)
                .orElseGet(() -> createNewDevice(fullDeviceId, user, metadata));

        updateDeviceInfo(deviceInfo, metadata, securityConfiguration);
//        calculateTrustScore(deviceInfo);
        deviceInfoRepository.save(deviceInfo);
        log.info("Device registered: {}", fullDeviceId);
    }

    @Override
    @Transactional
    public void registerDevice(String fullDeviceId, AuthUser user, Object securityConfiguration,
                               HttpServletRequest request) {
        registerDevice(fullDeviceId, user, securityConfiguration, deviceMetadataExtractor.extractDeviceMetadata(request));
    }

    @Override
    public boolean isDeviceTrusted(String fullDeviceId) {
        return false;
    }

    @Override
    public void updateDeviceTrustStatus(String fullDeviceId, boolean trusted) {

    }

    private DeviceInfo createNewDevice(String fullDeviceId, AuthUser user, DeviceMetadata metadata) {
        return DeviceInfo.builder()
                .fullDeviceId(fullDeviceId)
                .user(user)
                .deviceName(metadata.deviceName())
                .deviceType(metadata.deviceType())
                .osName(metadata.osName())
                .osVersion(metadata.osVersion())
                .browserName(metadata.browserName())
                .browserVersion(metadata.browserVersion())
                .ipAddress(metadata.ipAddress())
                .firstLoginTime(LocalDateTime.now())
                .lastLoginTime(LocalDateTime.now())
                .loginCount(0)
                .trustScore(0.5)
                .trusted(false)
                .trustExpiry(LocalDateTime.now().plusDays(7))
                .build();
    }

    private void updateDeviceInfo(DeviceInfo deviceInfo, DeviceMetadata metadata, Object securityConfig) {
        deviceInfo.setLastLoginTime(LocalDateTime.now());
        deviceInfo.setLoginCount(deviceInfo.getLoginCount() + 1);
        deviceInfo.setIpAddress(metadata.ipAddress());
        deviceInfo.setCountry(metadata.country());
        deviceInfo.setRegion(metadata.region());
        deviceInfo.setCity(metadata.city());
        deviceInfo.setSecurityConfiguration(securityConfig);
    }

    // ... (rest of the methods remain the same as in your original implementation)
}
package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.DeviceIdRequest;
import com.tj.services.ums.dto.DeviceIdResponse;
import com.tj.services.ums.model.DeviceInfo;
import com.tj.services.ums.repository.DeviceInfoRepository;
import com.tj.services.ums.service.DeviceManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class DeviceManagementServiceImpl implements DeviceManagementService {

    private final DeviceInfoRepository deviceInfoRepository;

    @Override
    @Transactional(readOnly = true)
    public DeviceIdResponse getDeviceIds(DeviceIdRequest request) {
        log.info("Device IDs requested for user: {}", request.userId());
        
        List<DeviceInfo> deviceInfos = deviceInfoRepository.findByUserId(request.userId());
        
        List<DeviceIdResponse.DeviceInfo> devices = deviceInfos.stream()
            .map(this::convertToDeviceInfo)
            .collect(Collectors.toList());
        
        return new DeviceIdResponse(request.userId(), devices);
    }

    private DeviceIdResponse.DeviceInfo convertToDeviceInfo(DeviceInfo entity) {
        return new DeviceIdResponse.DeviceInfo(
            entity.getFullDeviceId(),
            entity.getDeviceName(),
            entity.getDeviceType(),
            entity.getIpAddress(),
            entity.getUserAgent(),
            entity.getLastLoginTime(),
            true, // Assuming active if it exists in the database
            entity.isTrustedDevice()
        );
    }
} 
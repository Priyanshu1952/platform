package com.tj.services.ums.service;

import com.tj.services.ums.dto.DeviceIdRequest;
import com.tj.services.ums.dto.DeviceIdResponse;

/**
 * Service interface for device management operations
 */
public interface DeviceManagementService {
    
    /**
     * Retrieves a list of device IDs for a user
     */
    DeviceIdResponse getDeviceIds(DeviceIdRequest request);
} 
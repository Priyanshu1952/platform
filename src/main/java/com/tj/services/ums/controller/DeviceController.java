package com.tj.services.ums.controller;

import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.dto.DeviceIdRequest;
import com.tj.services.ums.dto.DeviceIdResponse;
import com.tj.services.ums.service.DeviceManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for device management operations
 */
@Slf4j
@RestController
@RequestMapping("/ums/v1/device")
@RequiredArgsConstructor
@Tag(name = "Device Management", description = "Endpoints for device management operations")
@SecurityRequirement(name = "bearerAuth")
public class DeviceController {

    private final DeviceManagementService deviceManagementService;

    /**
     * Retrieves a list of device IDs for a user
     */
    @PostMapping("/get-deviceId")
    @Operation(summary = "Get device IDs", description = "Retrieves a list of device IDs for a user")
    @PreAuthorize("hasRole('ADMIN') or #request.userId == authentication.principal.username")
    public ResponseEntity<ApiResponse> getDeviceIds(
            @Valid @RequestBody DeviceIdRequest request,
            HttpServletRequest httpRequest) {
        
        log.info("Device IDs requested for user: {}", request.userId());
        
        try {
            DeviceIdResponse response = deviceManagementService.getDeviceIds(request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse apiResponse = ApiResponse.builder()
                    .status(status)
                    .data(response)
                    .message("Device IDs retrieved successfully")
                    .build();
            
            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            log.error("Error retrieving device IDs for user: {}", request.userId(), e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error retrieving device IDs: " + e.getMessage())
                    .build();
            
            ApiResponse apiResponse = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(apiResponse);
        }
    }
} 
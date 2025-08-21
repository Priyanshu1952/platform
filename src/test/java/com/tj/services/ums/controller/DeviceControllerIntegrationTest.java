package com.tj.services.ums.controller;

import com.tj.services.ums.dto.DeviceIdRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class DeviceControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetDeviceId_Success() throws Exception {
        DeviceIdRequest request = new DeviceIdRequest(testUser.getUserId());

        mockMvc.perform(post("/api/v1/devices/get-deviceId")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.deviceId").exists());
    }

    @Test
    void testGetDeviceId_Unauthorized() throws Exception {
        DeviceIdRequest request = new DeviceIdRequest(testUser.getUserId());

        mockMvc.perform(post("/api/v1/devices/get-deviceId")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }
} 
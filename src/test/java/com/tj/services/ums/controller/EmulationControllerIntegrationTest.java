package com.tj.services.ums.controller;

import com.tj.services.ums.dto.EmulationRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class EmulationControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testEmulateUser_Success() throws Exception {
        EmulationRequest request = EmulationRequest.builder()
                .reason("Emulation reason for testing")
                .build();

        mockMvc.perform(post("/api/v1/emulation/emulate/" + testUser.getUserId())
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testEmulateUser_Forbidden() throws Exception {
        EmulationRequest request = EmulationRequest.builder()
                .reason("Emulation reason for testing")
                .build();

        mockMvc.perform(post("/api/v1/emulation/emulate/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void testEndEmulation_Success() throws Exception {
        mockMvc.perform(post("/api/v1/emulation/emulation/test-session-id/end")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetLinkedUsers_Success() throws Exception {
        mockMvc.perform(get("/api/v1/emulation/emulation/linked-users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetActiveSessions_Success() throws Exception {
        mockMvc.perform(get("/api/v1/emulation/emulation/sessions/active")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
} 
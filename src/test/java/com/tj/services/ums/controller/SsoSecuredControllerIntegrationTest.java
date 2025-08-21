package com.tj.services.ums.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class SsoSecuredControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetPublicInfo_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/public/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetSecureProfile_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/profile")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetSecureProfile_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetUserDashboard_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/user/dashboard")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetAgentBookings_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/agent/bookings")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetAdminUsers_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/admin/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetAdminUsers_Forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/sso/admin/users")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testGetSecureData_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/data")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testPostAdminConfig_Success() throws Exception {
        Map<String, Object> configData = Map.of(
                "key", "value",
                "enabled", true
        );

        mockMvc.perform(post("/api/v1/sso/admin/config")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(configData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetSecureSensitive_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/sensitive")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetSecureSensitive_Forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/sensitive")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testGetFinancialReports_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/secure/financial-reports")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetTokenInfo_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/token/info")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetHealth_Success() throws Exception {
        mockMvc.perform(get("/api/v1/sso/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
} 
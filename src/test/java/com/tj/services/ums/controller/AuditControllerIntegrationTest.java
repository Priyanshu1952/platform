package com.tj.services.ums.controller;

import com.tj.services.ums.dto.AuditLogRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuditControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetAudits_Success() throws Exception {
        AuditLogRequest request = new AuditLogRequest(
                testUser.getUserId(),
                "LOGIN",
                "User login attempt",
                "192.168.1.1",
                "Mozilla/5.0",
                LocalDateTime.now().minusDays(7),
                LocalDateTime.now(),
                "DESC",
                0,
                10
        );

        mockMvc.perform(post("/api/v1/audits/audits")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetAudits_Unauthorized() throws Exception {
        AuditLogRequest request = new AuditLogRequest(
                testUser.getUserId(),
                "LOGIN",
                "User login attempt",
                "192.168.1.1",
                "Mozilla/5.0",
                LocalDateTime.now().minusDays(7),
                LocalDateTime.now(),
                "DESC",
                0,
                10
        );

        mockMvc.perform(post("/api/v1/audits/audits")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetAudits_Forbidden() throws Exception {
        AuditLogRequest request = new AuditLogRequest(
                testUser.getUserId(),
                "LOGIN",
                "User login attempt",
                "192.168.1.1",
                "Mozilla/5.0",
                LocalDateTime.now().minusDays(7),
                LocalDateTime.now(),
                "DESC",
                0,
                10
        );

        mockMvc.perform(post("/api/v1/audits/audits")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isForbidden());
    }
} 
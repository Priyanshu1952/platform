package com.tj.services.ums.controller;

import com.tj.services.ums.dto.TokenRefreshRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class TokenControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testRefreshToken_Success() throws Exception {
        // First login to get refresh token
        String loginResponse = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(new com.tj.services.ums.dto.LoginRequest("user@test.com", "UserPass123!"))))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        com.tj.services.ums.dto.LoginResponse loginResponseObj = objectMapper.readValue(loginResponse, com.tj.services.ums.dto.LoginResponse.class);
        
        TokenRefreshRequest refreshRequest = new TokenRefreshRequest(loginResponseObj.getRefreshToken());

        mockMvc.perform(post("/api/v1/tokens/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    void testValidateToken_Success() throws Exception {
        mockMvc.perform(post("/api/v1/tokens/validate")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void testValidateToken_InvalidToken() throws Exception {
        mockMvc.perform(post("/api/v1/tokens/validate")
                .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testValidateToken_NoToken() throws Exception {
        mockMvc.perform(post("/api/v1/tokens/validate"))
                .andExpect(status().isUnauthorized());
    }
} 
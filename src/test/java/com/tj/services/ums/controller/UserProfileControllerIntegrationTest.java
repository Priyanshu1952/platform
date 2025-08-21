package com.tj.services.ums.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class UserProfileControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetUserProfile_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-profiles/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetUserProfile_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/user-profiles/" + testUser.getUserId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testUpdateUserProfile_Success() throws Exception {
        Map<String, Object> profileData = Map.of(
                "name", "Updated Profile Name",
                "bio", "Updated bio",
                "preferences", Map.of("theme", "dark")
        );

        mockMvc.perform(put("/api/v1/user-profiles/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(profileData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetMyProfile_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-profiles/me")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testUpdateMyProfile_Success() throws Exception {
        Map<String, Object> profileData = Map.of(
                "name", "My Updated Profile",
                "bio", "My updated bio"
        );

        mockMvc.perform(put("/api/v1/user-profiles/me")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(profileData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
} 
package com.tj.services.ums.controller;

import com.tj.services.ums.dto.UserRelationRequest;
import com.tj.services.ums.model.RelationshipType;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class UserRelationshipControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetAllowedUsers_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-relationships/allowed-users/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetAllowedUsers_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/user-relationships/allowed-users/" + testUser.getUserId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testCreateRelationship_Success() throws Exception {
        UserRelationRequest request = UserRelationRequest.builder()
                .userId1(testUser.getUserId())
                .userId2(adminUser.getUserId())
                .relationshipType(RelationshipType.PARENT_CHILD)
                .build();

        mockMvc.perform(post("/api/v1/user-relationships/create")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testCreateRelationship_Unauthorized() throws Exception {
        UserRelationRequest request = UserRelationRequest.builder()
                .userId1(testUser.getUserId())
                .userId2(adminUser.getUserId())
                .relationshipType(RelationshipType.PARENT_CHILD)
                .build();

        mockMvc.perform(post("/api/v1/user-relationships/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetUserRelationships_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-relationships/user/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetRelatedUsers_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-relationships/user/" + testUser.getUserId() + "/related-users")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testDeleteRelationship_Success() throws Exception {
        // Assuming there's a relationship with ID 1
        mockMvc.perform(delete("/api/v1/user-relationships/1")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetRelationshipTypes_Success() throws Exception {
        mockMvc.perform(get("/api/v1/user-relationships/types")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
} 
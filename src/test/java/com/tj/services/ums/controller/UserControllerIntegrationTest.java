package com.tj.services.ums.controller;

import com.tj.services.ums.dto.UserUpdateRequest;
import com.tj.services.ums.model.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class UserControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetUserById_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true))
                .andExpect(jsonPath("$.data").exists());
    }

    @Test
    void testGetUserById_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/users/" + testUser.getUserId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetUserById_Forbidden() throws Exception {
        // User trying to access another user's data
        mockMvc.perform(get("/api/v1/users/" + adminUser.getUserId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testGetAuthUserById_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/auth/" + testAuthUser.getId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true))
                .andExpect(jsonPath("$.data").exists());
    }

    @Test
    void testUpdateUser_Success() throws Exception {
        UserUpdateRequest request = UserUpdateRequest.builder()
                .name("Updated User Name")
                .email("updated@test.com")
                .mobile("+919876543214")
                .phone("Updated Phone")
                .status(UserStatus.ACTIVE)
                .additionalInfo(Map.of("key", "value"))
                .build();

        mockMvc.perform(put("/api/v1/users/" + testUser.getUserId())
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateAuthUser_Success() throws Exception {
        UserUpdateRequest request = UserUpdateRequest.builder()
                .name("Updated Auth User")
                .email("updatedauth@test.com")
                .mobile("+919876543215")
                .phone("Updated Phone")
                .status(UserStatus.ACTIVE)
                .additionalInfo(Map.of("key", "value"))
                .build();

        mockMvc.perform(put("/api/v1/users/auth/" + testAuthUser.getId())
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserProfile_Success() throws Exception {
        Map<String, Object> profileData = Map.of(
                "name", "Updated Profile Name",
                "bio", "Updated bio",
                "preferences", Map.of("theme", "dark")
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/profile")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(profileData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserAddress_Success() throws Exception {
        Map<String, Object> addressData = Map.of(
                "street", "Updated Street",
                "city", "Updated City",
                "state", "Updated State",
                "pincode", "654321"
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/address")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(addressData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserContact_Success() throws Exception {
        Map<String, Object> contactData = Map.of(
                "email", "updatedcontact@test.com",
                "mobile", "+919876543216",
                "phone", "1234567890"
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/contact")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(contactData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserKyc_Success() throws Exception {
        Map<String, Object> kycData = Map.of(
                "panNumber", "ABCDE1234F",
                "aadhaarNumber", "123456789012",
                "verified", true
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/kyc")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(kycData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateAuthUserSecurity_Success() throws Exception {
        Map<String, Object> securityData = Map.of(
                "require2fa", true,
                "deviceLimit", 3,
                "allowedIps", List.of("192.168.1.1", "10.0.0.1")
        );

        mockMvc.perform(patch("/api/v1/users/auth/" + testAuthUser.getId() + "/security")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(securityData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testVerifyEmail_Success() throws Exception {
        mockMvc.perform(post("/api/v1/users/auth/" + testAuthUser.getId() + "/verify/email")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testVerifyPan_Success() throws Exception {
        mockMvc.perform(post("/api/v1/users/auth/" + testAuthUser.getId() + "/verify/pan")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testVerifyAadhaar_Success() throws Exception {
        mockMvc.perform(post("/api/v1/users/auth/" + testAuthUser.getId() + "/verify/aadhaar")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testLockUser_Success() throws Exception {
        mockMvc.perform(post("/api/v1/users/auth/" + testAuthUser.getId() + "/lock")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUnlockUser_Success() throws Exception {
        mockMvc.perform(post("/api/v1/users/auth/" + testAuthUser.getId() + "/unlock")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserBalance_Success() throws Exception {
        Map<String, Object> balanceData = Map.of(
                "balance", 1000.0,
                "walletBalance", 500.0
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/balance")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(balanceData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testUpdateUserWalletBalance_Success() throws Exception {
        Map<String, Object> walletData = Map.of(
                "walletBalance", 750.0,
                "walletOrCreditStatus", "ACTIVE"
        );

        mockMvc.perform(patch("/api/v1/users/" + testUser.getUserId() + "/wallet-balance")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(walletData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testBulkUpdateUsers_Success() throws Exception {
        Map<String, Object> bulkUpdateData = Map.of(
                "userIds", List.of(testUser.getUserId()),
                "updates", Map.of("status", "ACTIVE")
        );

        mockMvc.perform(put("/api/v1/users/bulk/update")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(bulkUpdateData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testBulkActivateUsers_Success() throws Exception {
        Map<String, Object> bulkActivateData = Map.of(
                "userIds", List.of(testUser.getUserId())
        );

        mockMvc.perform(post("/api/v1/users/bulk/activate")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(bulkActivateData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testBulkDeactivateUsers_Success() throws Exception {
        Map<String, Object> bulkDeactivateData = Map.of(
                "userIds", List.of(testUser.getUserId())
        );

        mockMvc.perform(post("/api/v1/users/bulk/deactivate")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(bulkDeactivateData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testSearchUsers_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/search")
                .param("query", "test")
                .param("page", "0")
                .param("size", "10")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testGetUsersByRole_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/by-role/USER")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testGetUsersByStatus_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/by-status/ACTIVE")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testValidateEmail_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/validate/email")
                .param("email", "newemail@test.com")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testValidateMobile_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/validate/mobile")
                .param("mobile", "+919876543217")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }

    @Test
    void testValidateUserId_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/validate/user-id")
                .param("userId", "new-user-id")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.success").value(true));
    }
} 
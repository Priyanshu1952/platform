package com.tj.services.ums.controller;

import com.tj.services.ums.dto.KycVerificationRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class KycControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testVerifyPan_Success() throws Exception {
        KycVerificationRequest request = new KycVerificationRequest();
        request.setPanNumber("ABCDE1234F");

        mockMvc.perform(post("/api/v1/kyc/pan")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testVerifyPan_Unauthorized() throws Exception {
        KycVerificationRequest request = new KycVerificationRequest();
        request.setPanNumber("ABCDE1234F");

        mockMvc.perform(post("/api/v1/kyc/pan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testVerifyAadhaar_Success() throws Exception {
        KycVerificationRequest request = new KycVerificationRequest();
        request.setAadhaarNumber("123456789012");

        mockMvc.perform(post("/api/v1/kyc/aadhaar")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testVerifyAadhaar_Unauthorized() throws Exception {
        KycVerificationRequest request = new KycVerificationRequest();
        request.setAadhaarNumber("123456789012");

        mockMvc.perform(post("/api/v1/kyc/aadhaar")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }
}

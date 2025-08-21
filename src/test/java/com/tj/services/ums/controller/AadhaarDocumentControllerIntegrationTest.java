package com.tj.services.ums.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AadhaarDocumentControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testRequestOtp_Success() throws Exception {
        mockMvc.perform(post("/api/v1/aadhaar-documents/request-otp")
                .header("Authorization", "Bearer " + userToken)
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testRequestOtp_Unauthorized() throws Exception {
        mockMvc.perform(post("/api/v1/aadhaar-documents/request-otp")
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testDownloadDocument_Success() throws Exception {
        mockMvc.perform(post("/api/v1/aadhaar-documents/download")
                .header("Authorization", "Bearer " + userToken)
                .param("aadhaarNumber", "123456789012")
                .param("otp", "123456"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testDownloadDocument_Unauthorized() throws Exception {
        mockMvc.perform(post("/api/v1/aadhaar-documents/download")
                .param("aadhaarNumber", "123456789012")
                .param("otp", "123456"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testUploadDocument_Success() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "test.pdf",
                "application/pdf",
                "test content".getBytes()
        );

        mockMvc.perform(multipart("/api/v1/aadhaar-documents/upload")
                .file(file)
                .header("Authorization", "Bearer " + userToken)
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testUploadDocument_Unauthorized() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "test.pdf",
                "application/pdf",
                "test content".getBytes()
        );

        mockMvc.perform(multipart("/api/v1/aadhaar-documents/upload")
                .file(file)
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testDownloadStoredDocument_Success() throws Exception {
        mockMvc.perform(get("/api/v1/aadhaar-documents/download-stored")
                .header("Authorization", "Bearer " + userToken)
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isOk());
    }

    @Test
    void testDownloadStoredDocument_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/aadhaar-documents/download-stored")
                .param("aadhaarNumber", "123456789012"))
                .andExpect(status().isUnauthorized());
    }
} 
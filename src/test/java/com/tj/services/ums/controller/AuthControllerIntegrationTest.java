package com.tj.services.ums.controller;

import com.tj.services.ums.dto.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testLogin_Success() throws Exception {
        LoginRequest request = new LoginRequest("test-user@example.com", "UserPass123!");
        
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.user").exists())
                .andExpect(header().string("X-Auth-Method", "password"));
    }

    @Test
    void testLogin_InvalidCredentials() throws Exception {
        LoginRequest request = new LoginRequest("test-user@example.com", "WrongPassword");
        
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testRegister_Success() throws Exception {
        AddressRequest.CityInfoRequest cityInfo = new AddressRequest.CityInfoRequest("Test State", "India");
        AddressRequest address = new AddressRequest("123456", "123 Test St", cityInfo);
        
        RegisterRequest request = new RegisterRequest(
                "New User",
                "newuser@test.com",
                "NewUserPass123!",
                "+919876543213",
                address,
                "USER"
        );
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").exists())
                .andExpect(jsonPath("$.name").value("New User"))
                .andExpect(jsonPath("$.email").value("newuser@test.com"))
                .andExpect(jsonPath("$.mobile").value("+919876543213"))
                .andExpect(jsonPath("$.message").value("User registered successfully"))
                .andExpect(header().string("X-Account-Status", "pending_verification"));
    }

    @Test
    void testRegister_DuplicateEmail() throws Exception {
        AddressRequest.CityInfoRequest cityInfo = new AddressRequest.CityInfoRequest("Test State", "India");
        AddressRequest address = new AddressRequest("123456", "123 Test St", cityInfo);
        
        RegisterRequest request = new RegisterRequest(
                "New User",
                "test-user@example.com", // Already exists
                "NewUserPass123!",
                "+919876543213",
                address,
                "USER"
        );
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testOtpEmailRequest_Success() throws Exception {
        EmailOtpRequest request = new EmailOtpRequest("test-user@example.com", "device123");
        
        mockMvc.perform(post("/api/v1/auth/otp/email/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testOtpEmailLogin_Success() throws Exception {
        EmailOtpLoginRequest request = new EmailOtpLoginRequest("test-user@example.com", "123456", "device123");
        
        mockMvc.perform(post("/api/v1/auth/otp/email/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(header().string("X-Auth-Method", "otp_email"));
    }

    @Test
    void testOtpLogin_Success() throws Exception {
        OtpLoginRequest request = new OtpLoginRequest("+919876543212", "123456", "device123");
        
        mockMvc.perform(post("/api/v1/auth/otp/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(header().string("X-Auth-Method", "otp"));
    }

    @Test
    void testRefreshToken_Success() throws Exception {
        // First login to get refresh token
        LoginRequest loginRequest = new LoginRequest("user@test.com", "UserPass123!");
        String loginResponse = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(loginRequest)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        
        LoginResponse loginResponseObj = objectMapper.readValue(loginResponse, LoginResponse.class);
        
        TokenRefreshRequest refreshRequest = new TokenRefreshRequest(loginResponseObj.getRefreshToken());
        
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    void testLogout_Success() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNoContent());
    }

    @Test
    void testAdminEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/v1/auth/admin")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Welcome, Admin!"));
    }

    @Test
    void testAdminEndpoint_WithoutAdminRole() throws Exception {
        mockMvc.perform(get("/api/v1/auth/admin")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testPasswordResetRequest_Success() throws Exception {
        PasswordResetTokenRequest request = new PasswordResetTokenRequest("test-user@example.com");
        
        mockMvc.perform(post("/api/v1/auth/password/reset-request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk());
    }

    @Test
    void testPasswordReset_Success() throws Exception {
        PasswordResetRequest request = new PasswordResetRequest("test-user@example.com", "token123", "NewPassword123!");
        
        mockMvc.perform(post("/api/v1/auth/password/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createJson(request)))
                .andExpect(status().isOk());
    }

    @Test
    void testVerifyEmail_Success() throws Exception {
        mockMvc.perform(get("/api/v1/auth/verify-email")
                .param("token", "valid-token"))
                .andExpect(status().isOk())
                .andExpect(content().string("Email verified successfully!"));
    }

    @Test
    void testVerifyEmail_InvalidToken() throws Exception {
        mockMvc.perform(get("/api/v1/auth/verify-email")
                .param("token", "invalid-token"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid or expired verification token."));
    }

    @Test
    void testTestSms() throws Exception {
        mockMvc.perform(get("/api/v1/auth/test-sms"))
                .andExpect(status().isOk())
                .andExpect(content().string("Sent"));
    }
} 
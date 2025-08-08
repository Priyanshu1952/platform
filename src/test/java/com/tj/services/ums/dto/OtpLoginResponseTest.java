package com.tj.services.ums.dto;

import com.tj.services.ums.model.User;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OtpLoginResponseTest {

    @Test
    void testOtpLoginResponseStructure() {
        // Create a test user
        User user = new User();
        user.setId(1L);
        user.setName("Test User");
        user.setEmail("test@example.com");
        user.setMobile("1234567890");
        
        // Create OtpLoginResponse
        OtpLoginResponse response = new OtpLoginResponse();
        response.setSuccess(true);
        response.setMessage("OTP login successful");
        response.setUser(user);
        response.setAccessToken("test-access-token");
        response.setRefreshToken("test-refresh-token");
        response.setTwoDAuthRequired(false);
        
        // Verify all fields are set correctly
        assertTrue(response.isSuccess());
        assertEquals("OTP login successful", response.getMessage());
        assertNotNull(response.getUser());
        assertEquals("Test User", response.getUser().getName());
        assertEquals("test@example.com", response.getUser().getEmail());
        assertEquals("test-access-token", response.getAccessToken());
        assertEquals("test-refresh-token", response.getRefreshToken());
        assertFalse(response.getTwoDAuthRequired());
    }
    
    @Test
    void testOtpLoginResponseWithTwoFARequired() {
        User user = new User();
        user.setName("Test User");
        user.setEmail("test@example.com");
        
        OtpLoginResponse response = new OtpLoginResponse();
        response.setSuccess(true);
        response.setMessage("OTP login successful");
        response.setUser(user);
        response.setAccessToken("test-access-token");
        response.setRefreshToken("test-refresh-token");
        response.setTwoDAuthRequired(true);
        
        assertTrue(response.getTwoDAuthRequired());
    }
} 
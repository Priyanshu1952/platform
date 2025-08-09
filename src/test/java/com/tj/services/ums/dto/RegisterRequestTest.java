package com.tj.services.ums.dto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RegisterRequestTest {

    @Test
    void testValidRegisterRequest() {
        // Create valid address components
        AddressRequest.CityInfoRequest cityInfo = new AddressRequest.CityInfoRequest("Delhi", "India");
        AddressRequest address = new AddressRequest("110006", "Delhi", cityInfo);
        
        // Create valid register request
        RegisterRequest request = new RegisterRequest(
            "ioio Pandey",
            "uerw@gmail.com",
            "testuser1nikl",
            "9188958190",
            address,
            "AGENT"
        );
        
        // Verify all fields are set correctly
        assertEquals("ioio Pandey", request.name());
        assertEquals("uerw@gmail.com", request.email());
        assertEquals("testuser1nikl", request.password());
        assertEquals("9188958190", request.mobile());
        assertEquals("AGENT", request.role());
        
        // Verify address structure
        assertNotNull(request.address());
        assertEquals("110006", request.address().getPincode());
        assertEquals("Delhi", request.address().getAddress());
        assertEquals("Delhi", request.address().getCityInfo().getState());
        assertEquals("India", request.address().getCityInfo().getCountry());
    }
    
    @Test
    void testRoleValidation() {
        AddressRequest.CityInfoRequest cityInfo = new AddressRequest.CityInfoRequest("Delhi", "India");
        AddressRequest address = new AddressRequest("110006", "Delhi", cityInfo);
        
        // Test valid roles
        assertDoesNotThrow(() -> new RegisterRequest("Test", "test@test.com", "password123!", "1234567890", address, "USER"));
        assertDoesNotThrow(() -> new RegisterRequest("Test", "test@test.com", "password123!", "1234567890", address, "AGENT"));
        assertDoesNotThrow(() -> new RegisterRequest("Test", "test@test.com", "password123!", "1234567890", address, "ADMIN"));
    }
} 
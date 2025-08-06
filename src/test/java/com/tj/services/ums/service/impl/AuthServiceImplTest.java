package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.DeviceMetadata;
import com.tj.services.ums.dto.RegisterRequest;
import com.tj.services.ums.dto.RegisterResponse;
import com.tj.services.ums.exception.AuthException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.Role;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserStatus;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.RoleRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.DeviceService;
import com.tj.services.ums.service.GeoLocationService;
import com.tj.services.ums.service.LoginAuditService;
import com.tj.services.ums.service.OtpService;
import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.helper.DeviceMetadataExtractor;
import com.tj.services.ums.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@ActiveProfiles("test")
class AuthServiceImplTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private OtpService otpService;

    @Mock
    private DeviceService deviceService;

    @Mock
    private GeoLocationService geoLocationService;

    @Mock
    private LoginAuditService loginAuditService;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private DeviceMetadataExtractor deviceMetadataExtractor;

    @Mock
    private HttpServletRequest httpRequest;

    @InjectMocks
    private AuthServiceImpl authService;

    @Captor
    private ArgumentCaptor<AuthUser> authUserCaptor;
    @Captor
    private ArgumentCaptor<User> userCaptor;
    @Captor
    private ArgumentCaptor<String> deviceIdCaptor;

    private AuthUser testAuthUser;
    private User testUser;
    private RegisterRequest registerRequest;
    private DeviceMetadata testDeviceMetadata;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Initialize test data
        testAuthUser = new AuthUser();
        testAuthUser.setId(UUID.randomUUID());
        testAuthUser.setEmail("test@example.com");
        testAuthUser.setPassword("encodedPassword");
        
        testUser = new User();
        testUser.setId(1L);
        testUser.setName("Test User");
        testUser.setEmail("test@example.com");
        testUser.setMobile("+1234567890");
        testUser.setStatus(UserStatus.ACTIVE);
        
        registerRequest = new RegisterRequest(
            "Test User",
            "test@example.com",
            "ValidPass123!",
            "+1234567890"
        );
        
        httpRequest = mock(HttpServletRequest.class);
        when(httpRequest.getRemoteAddr()).thenReturn("192.168.1.1");
        when(httpRequest.getHeader("User-Agent")).thenReturn("Test User Agent");
        
        testDeviceMetadata = DeviceMetadata.builder()
            .deviceId("test-device")
            .deviceType("Test Device")
            .osName("Test OS")
            .osVersion("1.0")
            .browserName("Test Browser")
            .ipAddress("192.168.1.1")
            .build();
        
        userRole = new Role();
        userRole.setName("ROLE_USER");
        
        // Initialize mocks with MockitoExtension
        // No need for MockitoAnnotations.openMocks() when using MockitoExtension
        
        // Common stubs
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(deviceMetadataExtractor.extractDeviceMetadata(any(HttpServletRequest.class)))
            .thenReturn(testDeviceMetadata);
    }

    @Test
    void register_NewUser_ReturnsRegisterResponse() {
        // Arrange - No existing user
        when(authUserRepository.existsByEmail(registerRequest.email()))
            .thenReturn(false);
        
        // Mock saving the auth user
        when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
            AuthUser user = invocation.getArgument(0);
            user.setId(testAuthUser.getId());
            return user;
        });
        
        // Mock saving the user
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(testUser.getId());
            return user;
        });

        // Mock role repository
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));

        // Act
        RegisterResponse response = authService.register(registerRequest, httpRequest);

        // Assert
        assertNotNull(response, "Response should not be null");
        assertEquals(testAuthUser.getId(), response.userId(), "User ID should match");
        assertEquals(registerRequest.name(), response.name(), "Name should match");
        assertEquals(registerRequest.email(), response.email(), "Email should match");
        assertEquals(registerRequest.mobile(), response.mobile(), "Mobile should match");
        
        // Verify the device ID format
        assertNotNull(response.deviceId(), "Device ID should not be null");
        assertTrue(response.deviceId().startsWith("device_"), "Device ID should start with 'device_'");
    }

    @Test
    void register_DuplicateEmail_ThrowsException() {
        // Arrange - Email already exists
        when(authUserRepository.existsByEmail(registerRequest.email()))
                .thenReturn(true);

        // Act & Assert
        AuthException exception = assertThrows(AuthException.class, 
            () -> authService.register(registerRequest, httpRequest));
            
        // Verify exception message
        assertEquals("Email already registered", exception.getMessage());
    }

    @Test
    void register_InvalidPassword_ThrowsException() {
        // Arrange - Create a request with an invalid password (too short)
        RegisterRequest invalidPasswordRequest = new RegisterRequest(
                "Test User",
                "test@example.com",
                "weak", // Invalid password - too short
                "+1234567890"
        );

        // Act & Assert
        AuthException exception = assertThrows(AuthException.class, 
            () -> authService.register(invalidPasswordRequest, httpRequest));
            
        // Verify exception message indicates password policy violation
        assertTrue(exception.getMessage().contains("Password must be"), 
            "Error message should indicate password policy violation");
    }
}

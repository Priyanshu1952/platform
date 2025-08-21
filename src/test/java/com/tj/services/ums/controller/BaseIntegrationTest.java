package com.tj.services.ums.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tj.services.ums.UmsApplication;
import com.tj.services.ums.config.TestConfig;
import com.tj.services.ums.dto.LoginRequest;
import com.tj.services.ums.dto.LoginResponse;
import com.tj.services.ums.dto.RegisterRequest;
import com.tj.services.ums.dto.RegisterResponse;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserRole;
import com.tj.services.ums.model.UserStatus;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.AuthService;
import com.tj.services.ums.utils.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {UmsApplication.class, TestConfig.class})
@AutoConfigureWebMvc
@ActiveProfiles("test")
@Transactional
public abstract class BaseIntegrationTest {

    @Autowired
    protected WebApplicationContext webApplicationContext;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected AuthService authService;

    @Autowired
    protected AuthUserRepository authUserRepository;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected PasswordEncoder passwordEncoder;

    @Autowired
    protected JwtUtil jwtUtil;

    protected MockMvc mockMvc;

    protected String adminToken;
    protected String userToken;
    protected AuthUser testAuthUser;
    protected User testUser;
    protected AuthUser adminAuthUser;
    protected User adminUser;

    @BeforeEach
    void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        
        // Clean up any existing test users
        cleanupTestUsers();
        
        // Create test users
        createTestUsers();
        
        // Get authentication tokens
        adminToken = getAuthToken("test-admin@example.com", "AdminPass123!");
        userToken = getAuthToken("test-user@example.com", "UserPass123!");
    }

    private void cleanupTestUsers() {
        // Delete test users if they exist
        authUserRepository.findByEmail("test-admin@example.com").ifPresent(authUserRepository::delete);
        authUserRepository.findByEmail("test-user@example.com").ifPresent(authUserRepository::delete);
    }

    private void createTestUsers() {
        // Create admin user
        adminAuthUser = new AuthUser();
        adminAuthUser.setName("Test Admin User");
        adminAuthUser.setEmail("test-admin@example.com");
        adminAuthUser.setPassword(passwordEncoder.encode("AdminPass123!"));
        adminAuthUser.setMobile("+919876543211");
        adminAuthUser.setEmailVerified(true);
        adminAuthUser.setActive(true);
        adminAuthUser.setRequire2fa(false);
        adminAuthUser = authUserRepository.save(adminAuthUser);

        adminUser = new User();
        adminUser.setUserId(adminAuthUser.getId().toString());
        adminUser.setName("Test Admin User");
        adminUser.setEmail(adminAuthUser.getEmail());
        adminUser.setMobile(adminAuthUser.getMobile());
        adminUser.setRole(UserRole.ADMIN);
        adminUser.setStatus(UserStatus.ACTIVE);
        adminUser = userRepository.save(adminUser);

        // Create regular user
        testAuthUser = new AuthUser();
        testAuthUser.setName("Test User");
        testAuthUser.setEmail("test-user@example.com");
        testAuthUser.setPassword(passwordEncoder.encode("UserPass123!"));
        testAuthUser.setMobile("+919876543212");
        testAuthUser.setEmailVerified(true);
        testAuthUser.setActive(true);
        testAuthUser.setRequire2fa(false);
        testAuthUser = authUserRepository.save(testAuthUser);

        testUser = new User();
        testUser.setUserId(testAuthUser.getId().toString());
        testUser.setName("Test User");
        testUser.setEmail(testAuthUser.getEmail());
        testUser.setMobile(testAuthUser.getMobile());
        testUser.setRole(UserRole.USER);
        testUser.setStatus(UserStatus.ACTIVE);
        testUser = userRepository.save(testUser);
    }

    private String getAuthToken(String email, String password) throws Exception {
        LoginRequest loginRequest = new LoginRequest(email, password);
        
        String response = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        LoginResponse loginResponse = objectMapper.readValue(response, LoginResponse.class);
        return loginResponse.getAccessToken();
    }

    protected String createJson(Object obj) throws Exception {
        return objectMapper.writeValueAsString(obj);
    }
} 
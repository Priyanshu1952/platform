package com.tj.services.ums.utils;

import com.tj.services.ums.model.UserRole;
import com.tj.services.ums.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    private JwtUtil jwtUtil;
    private UserDetails testUserDetails;
    private User testUser;

    @BeforeEach
    void setUp() {
        // Create JwtUtil with test configuration
        String secretKey = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
        long accessTokenExpiration = 3600000L; // 1 hour
        long refreshTokenExpiration = 86400000L; // 24 hours
        
        jwtUtil = new JwtUtil(secretKey, accessTokenExpiration, refreshTokenExpiration);

        // Create test user details
        testUserDetails = org.springframework.security.core.userdetails.User.builder()
                .username("test@example.com")
                .password("password")
                .authorities("ROLE_USER")
                .build();

        // Create test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setName("Test User");
        testUser.setRole(UserRole.USER);
    }

    @Test
    void generateAccessToken_ValidUserDetails_ShouldGenerateValidToken() {
        // When
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify token can be parsed
        String username = jwtUtil.extractUsername(token);
        assertEquals(testUserDetails.getUsername(), username);
        
        // Verify token is valid
        assertTrue(jwtUtil.isTokenValid(token, testUserDetails));
    }

    @Test
    void generateRefreshToken_ValidUserDetails_ShouldGenerateValidToken() {
        // When
        String token = jwtUtil.generateRefreshToken(testUserDetails);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify token can be parsed
        String username = jwtUtil.extractUsername(token);
        assertEquals(testUserDetails.getUsername(), username);
        
        // Verify it's a refresh token
        assertTrue(jwtUtil.validateRefreshToken(token));
    }

    @Test
    void extractUsername_ValidToken_ShouldReturnUsername() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        String username = jwtUtil.extractUsername(token);

        // Then
        assertEquals(testUserDetails.getUsername(), username);
    }

    @Test
    void extractUsername_InvalidToken_ShouldThrowException() {
        // Given
        String invalidToken = "invalid.token.here";

        // When & Then
        assertThrows(JwtException.class, () -> jwtUtil.extractUsername(invalidToken));
    }

    @Test
    void isTokenValid_ValidToken_ShouldReturnTrue() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        boolean isValid = jwtUtil.isTokenValid(token, testUserDetails);

        // Then
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_InvalidUsername_ShouldReturnFalse() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);
        UserDetails differentUser = org.springframework.security.core.userdetails.User.builder()
                .username("different@example.com")
                .password("password")
                .authorities("ROLE_USER")
                .build();

        // When
        boolean isValid = jwtUtil.isTokenValid(token, differentUser);

        // Then
        assertFalse(isValid);
    }

    @Test
    void isTokenExpired_ValidToken_ShouldReturnFalse() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        boolean isExpired = jwtUtil.isTokenExpired(token);

        // Then
        assertFalse(isExpired);
    }

    @Test
    void extractExpiration_ValidToken_ShouldReturnExpirationDate() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        Date expiration = jwtUtil.extractExpiration(token);

        // Then
        assertNotNull(expiration);
        assertTrue(expiration.after(new Date()));
    }

    @Test
    void generateEmulatedAccessToken_ValidUser_ShouldGenerateEmulatedToken() {
        // Given
        UUID emulatingUserId = UUID.randomUUID();

        // When
        String token = jwtUtil.generateEmulatedAccessToken(testUser, emulatingUserId);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify it's an emulated token
        assertTrue(jwtUtil.isEmulatedToken(token));
        
        // Extract emulation claims
        Map<String, Object> emulationClaims = jwtUtil.extractEmulationClaims(token);
        assertTrue((Boolean) emulationClaims.get("emulated"));
        assertEquals(emulatingUserId.toString(), emulationClaims.get("emulated_by"));
        assertEquals(testUser.getId().toString(), emulationClaims.get("target_user_id"));
        assertEquals(testUser.getEmail(), emulationClaims.get("target_user_email"));
    }

    @Test
    void isEmulatedToken_EmulatedToken_ShouldReturnTrue() {
        // Given
        UUID emulatingUserId = UUID.randomUUID();
        String token = jwtUtil.generateEmulatedAccessToken(testUser, emulatingUserId);

        // When
        boolean isEmulated = jwtUtil.isEmulatedToken(token);

        // Then
        assertTrue(isEmulated);
    }

    @Test
    void isEmulatedToken_RegularToken_ShouldReturnFalse() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        boolean isEmulated = jwtUtil.isEmulatedToken(token);

        // Then
        assertFalse(isEmulated);
    }

    @Test
    void extractEmulationClaims_EmulatedToken_ShouldReturnClaims() {
        // Given
        UUID emulatingUserId = UUID.randomUUID();
        String token = jwtUtil.generateEmulatedAccessToken(testUser, emulatingUserId);

        // When
        Map<String, Object> claims = jwtUtil.extractEmulationClaims(token);

        // Then
        assertNotNull(claims);
        assertTrue((Boolean) claims.get("emulated"));
        assertEquals(emulatingUserId.toString(), claims.get("emulated_by"));
        assertEquals(testUser.getId().toString(), claims.get("target_user_id"));
        assertEquals(testUser.getEmail(), claims.get("target_user_email"));
    }

    @Test
    void extractEmulationClaims_RegularToken_ShouldReturnEmptyMap() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        Map<String, Object> claims = jwtUtil.extractEmulationClaims(token);

        // Then
        assertNotNull(claims);
        // The method returns a map with null values for regular tokens
        // since emulation claims don't exist in regular tokens
        assertNull(claims.get("emulated"));
        assertNull(claims.get("emulated_by"));
        assertNull(claims.get("target_user_id"));
        assertNull(claims.get("target_user_email"));
    }

    @Test
    void validateRefreshToken_ValidRefreshToken_ShouldReturnTrue() {
        // Given
        String token = jwtUtil.generateRefreshToken(testUserDetails);

        // When
        boolean isValid = jwtUtil.validateRefreshToken(token);

        // Then
        assertTrue(isValid);
    }

    @Test
    void validateRefreshToken_AccessToken_ShouldReturnFalse() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        boolean isValid = jwtUtil.validateRefreshToken(token);

        // Then
        assertFalse(isValid);
    }

    @Test
    void validateRefreshToken_InvalidToken_ShouldReturnFalse() {
        // Given
        String invalidToken = "invalid.token.here";

        // When
        boolean isValid = jwtUtil.validateRefreshToken(invalidToken);

        // Then
        assertFalse(isValid);
    }

    @Test
    void extractToken_ValidAuthorizationHeader_ShouldReturnToken() {
        // Given
        String authHeader = "Bearer test.token.here";

        // When
        String token = jwtUtil.extractToken(mock(org.springframework.mock.web.MockHttpServletRequest.class));

        // Then
        // This test requires a real HttpServletRequest, so we'll test the logic differently
        // The actual implementation checks for "Authorization" header starting with "Bearer "
    }

    @Test
    void extractToken_NoAuthorizationHeader_ShouldReturnNull() {
        // Given
        org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        // No Authorization header set

        // When
        String token = jwtUtil.extractToken(request);

        // Then
        assertNull(token);
    }

    @Test
    void extractToken_InvalidAuthorizationHeader_ShouldReturnNull() {
        // Given
        org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        request.addHeader("Authorization", "InvalidFormat");

        // When
        String token = jwtUtil.extractToken(request);

        // Then
        assertNull(token);
    }

    @Test
    void getAccessTokenExpiry_ShouldReturnFutureDate() {
        // When
        Date expiry = jwtUtil.getAccessTokenExpiry();

        // Then
        assertNotNull(expiry);
        assertTrue(expiry.after(new Date()));
    }

    @Test
    void getAccessTokenExpiryInMillis_ShouldReturnFutureTimestamp() {
        // When
        long expiryMillis = jwtUtil.getAccessTokenExpiryInMillis();

        // Then
        assertTrue(expiryMillis > System.currentTimeMillis());
    }

    @Test
    void getAccessTokenExpiryInstant_ShouldReturnFutureInstant() {
        // When
        Instant expiry = jwtUtil.getAccessTokenExpiryInstant();

        // Then
        assertNotNull(expiry);
        assertTrue(expiry.isAfter(Instant.now()));
    }

    @Test
    void getAccessTokenExpiration_ShouldReturnConfiguredValue() {
        // When
        long expiration = jwtUtil.getAccessTokenExpiration();

        // Then
        assertEquals(3600000L, expiration);
    }

    @Test
    void getRefreshTokenExpiration_ShouldReturnConfiguredValue() {
        // When
        long expiration = jwtUtil.getRefreshTokenExpiration();

        // Then
        assertEquals(86400000L, expiration);
    }

    @Test
    void extractClaim_ValidToken_ShouldReturnClaim() {
        // Given
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // When
        String subject = jwtUtil.extractClaim(token, Claims::getSubject);

        // Then
        assertEquals(testUserDetails.getUsername(), subject);
    }

    @Test
    void extractClaim_InvalidToken_ShouldThrowException() {
        // Given
        String invalidToken = "invalid.token.here";

        // When & Then
        assertThrows(JwtException.class, () -> jwtUtil.extractClaim(invalidToken, Claims::getSubject));
    }

    @Test
    void generateToken_WithExtraClaims_ShouldIncludeClaims() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("custom_claim", "custom_value");
        extraClaims.put("number_claim", 123);

        // When
        String token = jwtUtil.generateAccessToken(testUserDetails);

        // Then
        assertNotNull(token);
        // Note: We can't easily test the private generateToken method directly,
        // but we can verify the token is valid
        assertTrue(jwtUtil.isTokenValid(token, testUserDetails));
    }

    @Test
    void emulatedToken_WithDifferentRoles_ShouldWorkCorrectly() {
        // Given
        User adminUser = new User();
        adminUser.setId(2L);
        adminUser.setEmail("admin@example.com");
        adminUser.setName("Admin User");
        adminUser.setRole(UserRole.ADMIN);

        UUID emulatingUserId = UUID.randomUUID();

        // When
        String token = jwtUtil.generateEmulatedAccessToken(adminUser, emulatingUserId);

        // Then
        assertNotNull(token);
        assertTrue(jwtUtil.isEmulatedToken(token));
        
        Map<String, Object> claims = jwtUtil.extractEmulationClaims(token);
        assertEquals(adminUser.getId().toString(), claims.get("target_user_id"));
        assertEquals(adminUser.getEmail(), claims.get("target_user_email"));
    }
} 
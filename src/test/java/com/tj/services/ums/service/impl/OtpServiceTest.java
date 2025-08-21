package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.SendOtpRequest;
import com.tj.services.ums.dto.SendOtpResponse;
import com.tj.services.ums.exception.InvalidOtpException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.OtpToken;
import com.tj.services.ums.model.OtpType;
import com.tj.services.ums.repository.OtpTokenRepository;
import com.tj.services.ums.service.EmailService;
import com.tj.services.ums.service.OtpService;
import com.tj.services.ums.service.SmsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock
    private OtpTokenRepository otpTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SmsService smsService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private OtpService otpService;

    private SendOtpRequest validRequest;
    private AuthUser testUser;
    private OtpToken testToken;

    @BeforeEach
    void setUp() {
        // Set up test configuration
        ReflectionTestUtils.setField(otpService, "otpLength", 6);
        ReflectionTestUtils.setField(otpService, "otpExpiryMinutes", 5);
        ReflectionTestUtils.setField(otpService, "maxAttempts", 3);
        ReflectionTestUtils.setField(otpService, "testModeEnabled", false);
        ReflectionTestUtils.setField(otpService, "testOtpValue", "123456");

        // Create test data
        validRequest = new SendOtpRequest(
                "test-device-123",
                "+919876543210",
                "test@example.com",
                OtpType.SMS
        );

        testUser = new AuthUser();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@example.com");
        testUser.setMobile("+919876543210");

        testToken = new OtpToken();
        testToken.setId(1L);
        testToken.setDeviceId("test-device-123");
        testToken.setMobile("+919876543210");
        testToken.setEmail("test@example.com");
        testToken.setOtpHash("hashed-otp-123");
        testToken.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
        testToken.setOtpType(OtpType.SMS);
        testToken.setConsumed(false);
        testToken.setAttempts(0);
    }

    @Test
    void sendOtp_Success_ShouldGenerateAndSendOtp() {
        // Given
        String generatedOtp = "123456";
        String hashedOtp = "hashed-otp-123";
        when(passwordEncoder.encode(anyString())).thenReturn(hashedOtp);
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        SendOtpResponse response = otpService.sendOtp(validRequest);

        // Then
        assertNotNull(response);
        assertEquals("OTP sent successfully", response.message());
        assertEquals(validRequest.deviceId(), response.deviceId());
        assertEquals(validRequest.otpType(), response.otpType());
        assertNotNull(response.expiresAt());

        // Verify OTP token was saved
        ArgumentCaptor<OtpToken> tokenCaptor = ArgumentCaptor.forClass(OtpToken.class);
        verify(otpTokenRepository).deleteByDeviceId(validRequest.deviceId());
        verify(otpTokenRepository).save(tokenCaptor.capture());

        OtpToken savedToken = tokenCaptor.getValue();
        assertEquals(validRequest.deviceId(), savedToken.getDeviceId());
        assertEquals(validRequest.mobile(), savedToken.getMobile());
        assertEquals(validRequest.email(), savedToken.getEmail());
        assertEquals(hashedOtp, savedToken.getOtpHash());
        assertEquals(validRequest.otpType(), savedToken.getOtpType());
        assertFalse(savedToken.isConsumed());
        assertEquals(0, savedToken.getAttempts());

        // Verify SMS was sent
        verify(smsService).sendOtp(eq(validRequest.mobile()), anyString(), eq(5));
        verify(emailService, never()).sendOtp(anyString(), anyString(), anyInt());
    }

    @Test
    void sendOtp_EmailType_ShouldSendEmailOnly() {
        // Given
        SendOtpRequest emailRequest = new SendOtpRequest(
                "test-device-123",
                "+919876543210",
                "test@example.com",
                OtpType.EMAIL
        );
        when(passwordEncoder.encode(anyString())).thenReturn("hashed-otp");
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        SendOtpResponse response = otpService.sendOtp(emailRequest);

        // Then
        assertNotNull(response);
        assertEquals(OtpType.EMAIL, response.otpType());

        // Verify email was sent, SMS was not
        verify(emailService).sendOtp(eq(emailRequest.email()), anyString(), eq(5));
        verify(smsService, never()).sendOtp(anyString(), anyString(), anyInt());
    }

    @Test
    void sendOtp_BothType_ShouldSendBothSmsAndEmail() {
        // Given
        SendOtpRequest bothRequest = new SendOtpRequest(
                "test-device-123",
                "+919876543210",
                "test@example.com",
                OtpType.BOTH
        );
        when(passwordEncoder.encode(anyString())).thenReturn("hashed-otp");
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        SendOtpResponse response = otpService.sendOtp(bothRequest);

        // Then
        assertNotNull(response);
        assertEquals(OtpType.BOTH, response.otpType());

        // Verify both SMS and email were sent
        verify(smsService).sendOtp(eq(bothRequest.mobile()), anyString(), eq(5));
        verify(emailService).sendOtp(eq(bothRequest.email()), anyString(), eq(5));
    }

    @Test
    void sendOtp_TestModeEnabled_ShouldUseFixedOtp() {
        // Given
        ReflectionTestUtils.setField(otpService, "testModeEnabled", true);
        ReflectionTestUtils.setField(otpService, "testOtpValue", "999999");
        when(passwordEncoder.encode("999999")).thenReturn("hashed-test-otp");
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        SendOtpResponse response = otpService.sendOtp(validRequest);

        // Then
        assertNotNull(response);
        verify(passwordEncoder).encode("999999");
    }

    @Test
    void validateOtp_ValidOtp_ShouldReturnTrue() {
        // Given
        String deviceId = "test-device-123";
        String otp = "123456";
        when(otpTokenRepository.findFirstByEmailAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(testUser.getEmail()), eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.of(testToken));
        when(passwordEncoder.matches(eq(otp), eq(testToken.getOtpHash()))).thenReturn(true);
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        boolean result = otpService.validateOtp(deviceId, otp, testUser);

        // Then
        assertTrue(result);
        verify(otpTokenRepository).save(argThat(token -> token.isConsumed()));
    }

    @Test
    void validateOtp_InvalidOtp_ShouldThrowException() {
        // Given
        String deviceId = "test-device-123";
        String otp = "123456";
        when(otpTokenRepository.findFirstByEmailAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(testUser.getEmail()), eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.of(testToken));
        when(passwordEncoder.matches(eq(otp), eq(testToken.getOtpHash()))).thenReturn(false);
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When & Then
        InvalidOtpException exception = assertThrows(InvalidOtpException.class,
                () -> otpService.validateOtp(deviceId, otp, testUser));
        assertEquals("Invalid OTP provided", exception.getMessage());

        // Verify attempts were incremented
        verify(otpTokenRepository).save(argThat(token -> token.getAttempts() == 1));
    }

    @Test
    void validateOtp_MaxAttemptsExceeded_ShouldThrowException() {
        // Given
        String deviceId = "test-device-123";
        String otp = "123456";
        testToken.setAttempts(3); // Max attempts reached
        when(otpTokenRepository.findFirstByEmailAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(testUser.getEmail()), eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.of(testToken));

        // When & Then
        InvalidOtpException exception = assertThrows(InvalidOtpException.class,
                () -> otpService.validateOtp(deviceId, otp, testUser));
        assertEquals("Maximum OTP attempts exceeded. Please request a new OTP.", exception.getMessage());

        // Verify token was deleted
        verify(otpTokenRepository).delete(testToken);
    }

    @Test
    void validateOtp_TokenNotFound_ShouldThrowException() {
        // Given
        String deviceId = "test-device-123";
        String otp = "123456";
        when(otpTokenRepository.findFirstByEmailAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(testUser.getEmail()), eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.empty());

        // When & Then
        InvalidOtpException exception = assertThrows(InvalidOtpException.class,
                () -> otpService.validateOtp(deviceId, otp, testUser));
        assertEquals("OTP not found, has expired, or has been consumed", exception.getMessage());
    }

    @Test
    void validateOtp_UserWithMobileOnly_ShouldUseMobileLookup() {
        // Given
        AuthUser mobileUser = new AuthUser();
        mobileUser.setId(UUID.randomUUID());
        mobileUser.setMobile("+919876543210");
        mobileUser.setEmail(null);

        String deviceId = "test-device-123";
        String otp = "123456";
        when(otpTokenRepository.findFirstByMobileAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(mobileUser.getMobile()), eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.of(testToken));
        when(passwordEncoder.matches(eq(otp), eq(testToken.getOtpHash()))).thenReturn(true);
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        boolean result = otpService.validateOtp(deviceId, otp, mobileUser);

        // Then
        assertTrue(result);
        verify(otpTokenRepository).findFirstByMobileAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                eq(mobileUser.getMobile()), eq(deviceId), any(Instant.class));
    }

    @Test
    void validateOtp_NoUser_ShouldUseDeviceIdLookup() {
        // Given
        String deviceId = "test-device-123";
        String otp = "123456";
        when(otpTokenRepository.findByDeviceIdAndConsumedFalseAndExpiresAtAfter(eq(deviceId), any(Instant.class)))
                .thenReturn(Optional.of(testToken));
        when(passwordEncoder.matches(eq(otp), eq(testToken.getOtpHash()))).thenReturn(true);
        when(otpTokenRepository.save(any(OtpToken.class))).thenReturn(testToken);

        // When
        boolean result = otpService.validateOtp(deviceId, otp, null);

        // Then
        assertTrue(result);
        verify(otpTokenRepository).findByDeviceIdAndConsumedFalseAndExpiresAtAfter(eq(deviceId), any(Instant.class));
    }

    @Test
    void generateOtp_TestModeDisabled_ShouldGenerateRandomOtp() {
        // Given
        ReflectionTestUtils.setField(otpService, "testModeEnabled", false);
        ReflectionTestUtils.setField(otpService, "otpLength", 6);

        // When
        SendOtpResponse response = otpService.sendOtp(validRequest);

        // Then
        assertNotNull(response);
        // Verify that a random OTP was generated (not the test value)
        verify(passwordEncoder).encode(argThat(otp -> !otp.equals("123456") && otp.length() == 6));
    }

    @Test
    void generateOtp_CustomLength_ShouldGenerateCorrectLength() {
        // Given
        ReflectionTestUtils.setField(otpService, "otpLength", 4);
        ReflectionTestUtils.setField(otpService, "testModeEnabled", false);

        // When
        SendOtpResponse response = otpService.sendOtp(validRequest);

        // Then
        assertNotNull(response);
        // Verify that a 4-digit OTP was generated
        verify(passwordEncoder).encode(argThat(otp -> otp.length() == 4));
    }
} 
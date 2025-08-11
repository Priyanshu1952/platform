package com.tj.services.ums.service;

import com.tj.services.ums.dto.SendOtpRequest;
import com.tj.services.ums.dto.SendOtpResponse;
import com.tj.services.ums.exception.InvalidOtpException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.OtpToken;
import com.tj.services.ums.model.OtpType;
import com.tj.services.ums.repository.OtpTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class OtpService {
    private static final Logger log = LoggerFactory.getLogger(OtpService.class);

    private final OtpTokenRepository otpTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final SmsService smsService; // Correctly injected
    private final EmailService emailService;
    private final Random random = new SecureRandom();

    @Value("${app.otp.length:6}")
    private int otpLength;

    @Value("${app.otp.expiry.minutes:5}")
    private int otpExpiryMinutes;

    @Value("${app.otp.max.attempts:3}")
    private int maxAttempts;

    @Autowired
    public OtpService(OtpTokenRepository otpTokenRepository, PasswordEncoder passwordEncoder, SmsService smsService, EmailService emailService) {
        this.otpTokenRepository = otpTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.smsService = smsService;
        this.emailService = emailService;
    }

    @Transactional
    public SendOtpResponse sendOtp(SendOtpRequest request) {
        String otp = generateOtp();
        log.info("[DEV] Generated OTP {} for device {} and mobile {}", otp, request.deviceId(), request.mobile());
        String hashedOtp = passwordEncoder.encode(otp);
        Instant expiry = Instant.now().plus(otpExpiryMinutes, ChronoUnit.MINUTES);

        // Delete any existing OTP tokens for the same device
        otpTokenRepository.deleteByDeviceId(request.deviceId());

        // Save OTP to the database
        OtpToken token = new OtpToken();
        token.setDeviceId(request.deviceId());
        token.setMobile(request.mobile());
        token.setEmail(request.email());
        token.setOtpHash(hashedOtp);
        token.setExpiresAt(expiry);
        token.setOtpType(request.otpType());
        otpTokenRepository.save(token);

        // Send OTP via SMS, Email, or both
        if (request.otpType() == OtpType.SMS || request.otpType() == OtpType.BOTH) {
            smsService.sendOtp(request.mobile(), otp, otpExpiryMinutes);
        }
        if (request.otpType() == OtpType.EMAIL || request.otpType() == OtpType.BOTH) {
            emailService.sendOtp(request.email(), otp, otpExpiryMinutes);
        }

        return new SendOtpResponse("OTP sent successfully", request.deviceId(), expiry, request.otpType());
    }

    @Transactional
    public boolean validateOtp(String deviceId, String otp, AuthUser user) {
        Optional<OtpToken> tokenOpt;
        if (user != null && user.getEmail() != null) {
            tokenOpt = otpTokenRepository.findFirstByEmailAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(user.getEmail(), deviceId, Instant.now());
            log.info("[OTP] Lookup by email+deviceId: email={}, deviceId={}, found={}", user.getEmail(), deviceId, tokenOpt.isPresent());
        } else if (user != null && user.getMobile() != null) {
            tokenOpt = otpTokenRepository.findFirstByMobileAndDeviceIdAndConsumedFalseAndExpiresAtAfterOrderByCreatedAtDesc(user.getMobile(), deviceId, Instant.now());
            log.info("[OTP] Lookup by mobile+deviceId: mobile={}, deviceId={}, found={}", user.getMobile(), deviceId, tokenOpt.isPresent());
        } else {
            tokenOpt = otpTokenRepository.findByDeviceIdAndConsumedFalseAndExpiresAtAfter(deviceId, Instant.now());
            log.info("[OTP] Lookup fallback by deviceId: deviceId={}, found={}", deviceId, tokenOpt.isPresent());
        }

        if (tokenOpt.isEmpty()) {
            throw new InvalidOtpException("OTP not found, has expired, or has been consumed");
        }

        OtpToken token = tokenOpt.get();

        if (token.getAttempts() >= maxAttempts) {
            otpTokenRepository.delete(token);
            throw new InvalidOtpException("Maximum OTP attempts exceeded. Please request a new OTP.");
        }

        log.info("Comparing OTP: provided='{}', storedHash='{}'", otp, token.getOtpHash());
    boolean otpMatch = passwordEncoder.matches(otp, token.getOtpHash());
    log.info("OTP match result: {}", otpMatch);
    if (!otpMatch) {
            token.setAttempts(token.getAttempts() + 1);
            otpTokenRepository.save(token);
            throw new InvalidOtpException("Invalid OTP provided");
        }

        token.setConsumed(true);
        otpTokenRepository.save(token);

        return true;
    }

    private String generateOtp() {
        return String.format("%0" + otpLength + "d", random.nextInt((int) Math.pow(10, otpLength)));
    }
}

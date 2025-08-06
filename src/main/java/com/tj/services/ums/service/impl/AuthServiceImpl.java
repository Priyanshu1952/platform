package com.tj.services.ums.service.impl;

import com.tj.services.ums.model.OtpType;
import com.tj.services.ums.dto.*;
import com.tj.services.ums.exception.AuthException;
import com.tj.services.ums.exception.DeviceNotFoundException;
import com.tj.services.ums.exception.InvalidTokenException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.Role;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserStatus;
import com.tj.services.ums.dto.DeviceMetadata;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.RoleRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.*;

import com.tj.services.ums.utils.JwtUtil;
import com.tj.services.ums.helper.DeviceMetadataExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.security.auth.login.AccountLockedException;

import java.util.Map;
import java.util.HashMap;
import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String DEVICE_ID_HEADER = "deviceid";
    private static final String DEVICE_ID_FORMAT = "%s_%s";

    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final OtpService otpService;
    private final DeviceService deviceService;
    private final GeoLocationService geoLocationService;
    private final LoginAuditService loginAuditService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserDetailsService userDetailsService;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final DeviceMetadataExtractor deviceMetadataExtractor;

    @Override
    public SendOtpResponse sendOtpToEmail(com.tj.services.ums.dto.EmailOtpRequest request) {
        AuthUser user = authUserRepository.findByEmail(request.email())
                .orElseThrow(() -> new AuthException("User not found with email: " + request.email()));
        String fullDeviceId = request.deviceId(); // Already formatted during OTP generation
        SendOtpRequest sendOtpRequest = new SendOtpRequest(fullDeviceId, null, user.getEmail(), OtpType.EMAIL);
        return otpService.sendOtp(sendOtpRequest);
    }

    @Override
    public OtpLoginResponse emailOtpLogin(com.tj.services.ums.dto.EmailOtpLoginRequest request, jakarta.servlet.http.HttpServletRequest httpRequest) {
        log.info("Email OTP login attempt: email={}, deviceId={}", request.email(), request.deviceId());
        try {
            AuthUser user = authUserRepository.findByEmail(request.email())
                    .orElseThrow(() -> new AuthException("User not found with email: " + request.email()));
            String fullDeviceId = request.deviceId(); // Already formatted during OTP generation
            log.debug("Full device ID: {} for user ID: {}", fullDeviceId, user.getId());

            otpService.validateOtp(fullDeviceId, request.otp(), user);
            log.info("OTP validated for device {} and user {}", fullDeviceId, user.getId());

            DeviceMetadata metadata = deviceMetadataExtractor.extractDeviceMetadata(httpRequest);
            deviceService.registerDevice(
                    fullDeviceId,
                    user,
                    user.getSecurityConfiguration(),
                    metadata
            );
            log.info("Device registered: {} for user {}", fullDeviceId, user.getId());

            OtpLoginResponse response = createOtpLoginResponse(user);
            log.info("Email OTP login successful for user {}", user.getId());
            return response;
        } catch (Exception e) {
            log.error("Error during email OTP login: {}", e.getMessage(), e);
            throw e;
        }
    }
    

    // Regex patterns for password policy
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*[0-9].*");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\\\\|,.<>/?].*");
private static final int MAX_LOGIN_ATTEMPTS = 5;
private static final long LOCK_TIME_DURATION = 15 * 60 * 1000; // 15 minutes
private static final int MAX_OTP_ATTEMPTS = 3;
private static final long OTP_LOCK_TIME_DURATION = 5 * 60 * 1000; // 5 minutes


    @Override
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        final String remoteIp = httpRequest.getRemoteAddr();
        final String deviceId = httpRequest.getHeader(DEVICE_ID_HEADER);
        log.debug("Login request received with deviceId: {}", deviceId);

        authenticateUser(request.email(), request.password());
        AuthUser user = authUserRepository.findByEmail(request.email()).orElseThrow(() -> new AuthException("User not found"));
        log.info("User authenticated with ID: {}", user.getId());

        validateIpAccess(user, remoteIp);

        String fullDeviceId = formatDeviceId(deviceId, user.getId());

        if (isNewDevice(fullDeviceId)) {
            initiateTwoFactorAuthentication(fullDeviceId, user);
            return LoginResponse.twoFactorRequired("SMS");
        }

        completeLoginProcess(fullDeviceId, user, httpRequest);
        return createLoginResponse(user);
    }

    @Override
public OtpLoginResponse otpLogin(OtpLoginRequest request, HttpServletRequest httpRequest) {
        log.info("OTP login attempt: mobile={}, deviceId={}", request.mobile(), request.deviceId());
        try {
            AuthUser user = findUserByMobile(request.mobile());
            String fullDeviceId = request.deviceId(); // Already formatted during OTP generation
            log.debug("Full device ID: {} for user ID: {}", fullDeviceId, user.getId());

            otpService.validateOtp(fullDeviceId, request.otp(), user);
            log.info("OTP validated for device {} and user {}", fullDeviceId, user.getId());

            DeviceMetadata metadata = deviceMetadataExtractor.extractDeviceMetadata(httpRequest);
            deviceService.registerDevice(
                    fullDeviceId,
                    user,
                    user.getSecurityConfiguration(),
                    metadata
            );
            log.info("Device registered: {} for user {}", fullDeviceId, user.getId());

            OtpLoginResponse response = createOtpLoginResponse(user);
            log.info("OTP login successful for user {}", user.getId());
            return response;
        } catch (Exception e) {
            log.error("Error during OTP login: {}", e.getMessage(), e);
            throw e;
        }
    }

    

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request, HttpServletRequest httpServletRequest) {
        validateEmailUniqueness(request.email());
        validatePasswordPolicy(request.password());

        // Create and save AuthUser
        AuthUser authUser = createUserFromRequest(request, httpServletRequest);
        AuthUser savedAuthUser = authUserRepository.save(authUser);

        // Create and save User profile
        User user = createUserProfileFromRequest(request, savedAuthUser.getId());
        userRepository.save(user);

        // Register device
        DeviceMetadata metadata = deviceMetadataExtractor.extractDeviceMetadata(httpServletRequest);
        String deviceId = String.format("device_%s", savedAuthUser.getId());
        deviceService.registerDevice(deviceId, savedAuthUser, 
            savedAuthUser.getSecurityConfiguration(), metadata);

        return RegisterResponse.fromUser(savedAuthUser, deviceId);
    }
    
    /**
     * Creates a User profile from the registration request
     * @param request The registration request
     * @param userId The ID of the associated AuthUser
     * @return A new User instance with basic profile information
     */
    private User createUserProfileFromRequest(RegisterRequest request, UUID userId) {
        User user = new User();
        // Note: User ID will be auto-generated by JPA since it's a separate entity
        // The relationship between AuthUser and User is maintained via email
        user.setName(request.name());
        user.setEmail(request.email());
        user.setMobile(request.mobile());
        user.setCreatedOn(java.time.LocalDateTime.now());
        user.setStatus(UserStatus.ACTIVE);
        // Set other default values as needed
        return user;
    }

    // Helper methods
    void validatePasswordPolicy(String password) {

        if (password == null || password.length() < 8 || password.length() > 20) {
            throw new AuthException("Password must be between 8 and 20 characters");
        }

        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            throw new AuthException("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            throw new AuthException("Password must contain at least one lowercase letter");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            throw new AuthException("Password must contain at least one digit");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            throw new AuthException("Password must contain at least one special character");
        }

        System.out.println("All password checks passed!");
    }

    private void authenticateUser(String email, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            auth.isAuthenticated();
        } catch (Exception e) {
            throw new AuthException("Authentication failed", e);
        }
    }

    private AuthUser getAuthenticatedUser(String email, String password) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
        return (AuthUser) auth.getPrincipal();
    }

    private void validateIpAccess(AuthUser user, String remoteIp) {
        List<String> whitelistedIps = (List<String>) user.getSecurityConfiguration().get("allowedIps");
        if (!deviceService.isIpAllowed(whitelistedIps, remoteIp)) {
            loginAuditService.sendLoginAlertEmail(
                    user.getEmail(),
                    user.getName(),
                    remoteIp
            );
            throw new AuthException("Access denied from IP: " + remoteIp);
        }
    }

    private String formatDeviceId(String deviceId, UUID userId) {
        return String.format(DEVICE_ID_FORMAT, deviceId, userId);
    }

    private boolean isNewDevice(String fullDeviceId) {
        try {
            deviceService.getDeviceInfo(fullDeviceId);
            return false;
        } catch (DeviceNotFoundException e) {
            return true;
        }
    }

    private void initiateTwoFactorAuthentication(String fullDeviceId, AuthUser user) {
        otpService.sendOtp(new SendOtpRequest(fullDeviceId, user.getMobile(), user.getEmail(), OtpType.SMS));
    }

    private void completeLoginProcess(String fullDeviceId, AuthUser user, HttpServletRequest request) {
        DeviceMetadata metadata = deviceMetadataExtractor.extractDeviceMetadata(request);
        deviceService.registerDevice(
                fullDeviceId,
                user,
                user.getSecurityConfiguration(),
                metadata
        );
    }
private void checkLoginAttempts(AuthUser user) throws AccountLockedException {
    int failedAttempts = user.getSecurityConfigValue("failedAttempts", Integer.class);
    Long lockTime = user.getSecurityConfigValue("lockTime", Long.class);
    
    if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
        if (lockTime == null || System.currentTimeMillis() > lockTime + LOCK_TIME_DURATION) {
            // Reset after lock time expires
            Map<String, Object> securityConfig = user.getSecurityConfiguration();
            securityConfig.put("failedAttempts", 0);
            securityConfig.put("lockTime", null);
            user.setSecurityConfiguration(securityConfig);
            authUserRepository.save(user);
        } else {
            throw new AccountLockedException("Account is locked. Please try again later or reset your password.");
        }
    }
}
    private LoginResponse createLoginResponse(AuthUser user) {
        String token = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);
        return new LoginResponse(
                false, // twoFactorRequired
                token,
                refreshToken,
                jwtUtil.getAccessTokenExpiryInstant(),
                null, // otpDeliveryMethod
                new LoginResponse.UserInfo(
                        user.getId(),
                        user.getEmail(),
                        user.getName()
                )
        );
    }

    private AuthUser findUserByMobile(String mobile) {
        return authUserRepository.findByMobile(mobile)
                .orElseThrow(() -> new AuthException("Mobile number not registered"));
    }

    private OtpLoginResponse createOtpLoginResponse(AuthUser user) {
        String token = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);
        return new OtpLoginResponse(
                token,
                refreshToken,
                jwtUtil.getAccessTokenExpiryInstant()
        );
    }

    private void validateEmailUniqueness(String email) {
        if (authUserRepository.existsByEmail(email)) {
            throw new AuthException("Email already registered");
        }
    }

    private AuthUser createUserFromRequest(RegisterRequest request, HttpServletRequest httpServletRequest) {
        AuthUser user = new AuthUser();
        user.setEmail(request.email());
        user.setName(request.name());
        user.setMobile(request.mobile());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEmailVerified(true);
        Map<String, Object> defaultSecurityConfig = new HashMap<>();
        defaultSecurityConfig.put("require2fa", false);
        defaultSecurityConfig.put("allowedIps", Collections.emptyList());
        defaultSecurityConfig.put("deviceLimit", 5);
        defaultSecurityConfig.put("accountLocked", false);
        defaultSecurityConfig.put("failedAttempts", 0);
        defaultSecurityConfig.put("lastPasswordChange", System.currentTimeMillis());
        user.setSecurityConfiguration(defaultSecurityConfig);

        user.getSecurityConfiguration().put("allowedIps", List.of(httpServletRequest.getRemoteAddr(), "0:0:0:0:0:0:0:1"));
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

        user.setRoles(Set.of(userRole));
        return user;
    }

    @Override
    @Transactional
    public TokenRefreshResponse refreshToken(TokenRefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new InvalidTokenException("Refresh token is required");
        }

        String refreshToken = request.refreshToken();

        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!jwtUtil.isTokenValid(refreshToken, userDetails)) {
            throw new InvalidTokenException("Refresh token is not valid for this user");
        }

        String newAccessToken = jwtUtil.generateAccessToken(userDetails);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);
        Date expireAt = jwtUtil.getAccessTokenExpiry(); // Using the new method

        return new TokenRefreshResponse(
            "Token refreshed successfully",
            newAccessToken,
            newRefreshToken,
            expireAt
        );
    }

    @Override
    public void logout(HttpServletRequest request) {
        String token = null;
        String username = null;
        try {
            token = jwtUtil.extractToken(request);
            log.debug("[Logout] Extracted token: {}", token);
            if (token != null) {
                tokenBlacklistService.blacklistToken(token);
                username = jwtUtil.extractUsername(token);
                log.info("User logged out successfully. Token blacklisted for user: {}", username);
            } else {
                log.warn("[Logout] No token found in request");
            }
        } catch (Exception e) {
            log.error("[Logout] Exception during logout. Token: {}, Username: {}. Message: {}", token, username, e.getMessage(), e);
            // Do not rethrow the exception, as logout should not fail on token errors.
        }
    }
    @Transactional
    public boolean verifyEmail(String token) {
        log.info("Verifying email with token: {}", token);
        try {
            // Extract email from token
            String email = jwtUtil.extractUsername(token);
            if (email == null) {
                log.warn("Invalid email verification token: {}", token);
                return false;
            }
            // Find the user by email
            AuthUser user = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
            // Check if token is valid and not expired
            if (jwtUtil.isTokenExpired(token)) {
                log.warn("Expired email verification token for user: {}", email);
                return false;
            }
            // If user is already verified, return true
            if (user.isEmailVerified()) {
                log.info("Email already verified for user: {}", email);
                return true;
            }
            // Update user's email verification status
            user.setEmailVerified(true);
            authUserRepository.save(user);
            log.info("Email verified successfully for user: {}", email);
            return true;
        } catch (Exception e) {
            log.error("Error verifying email with token: " + token, e);
            return false;
        }
    }
}

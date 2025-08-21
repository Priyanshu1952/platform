package com.tj.services.ums.service.impl;

import com.tj.services.ums.constants.SecurityConstants;
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

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.security.auth.login.AccountLockedException;

import java.util.HashMap;
import java.util.Collections;
import com.tj.services.ums.model.AddressInfo;
import com.tj.services.ums.model.UserRole;
import org.springframework.beans.factory.annotation.Value;

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

    @Value("${app.security.device-2fa.enabled:true}")
    private boolean device2faEnabled;

    @Override
    public SendOtpResponse sendOtpToEmail(com.tj.services.ums.dto.EmailOtpRequest request) {
        AuthUser user = authUserRepository.findByEmail(request.email())
                .orElseThrow(() -> new AuthException("User not found with email: " + request.email()));
        String fullDeviceId = request.deviceId(); // Already formatted during OTP generation
        // For email OTP requests, mobile number is not required, so we can pass null
        // The OtpToken entity now allows null mobile field
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


    @Override
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        final String remoteIp = httpRequest.getRemoteAddr();
        final String deviceId = httpRequest.getHeader(DEVICE_ID_HEADER);
        log.debug("Login request received with deviceId: {}", deviceId);

        try {
            // Authenticate the user
            authenticateUser(request.email(), request.password());
            
            // Get the user from the database
            AuthUser authUser = authUserRepository.findByEmail(request.email())
                .orElseThrow(() -> new AuthException("User not found"));
                
            log.info("User authenticated with ID: {}", authUser.getId());

            // Validate IP access
            validateIpAccess(authUser, remoteIp);

            // Format the device ID - use a default if not provided
            String fullDeviceId = formatDeviceId(deviceId != null ? deviceId : "default", authUser.getId());

            // Check if this is a new device (requires 2FA)
            if (isNewDevice(fullDeviceId)) {
                // Get or create user profile
                User user = userRepository.findByEmail(authUser.getEmail())
                    .orElseGet(() -> {
                        // Create a basic user profile if it doesn't exist
                        User newUser = new User();
                        newUser.setEmail(authUser.getEmail());
                        newUser.setName(authUser.getName());
                        return userRepository.save(newUser);
                    });
                
                // Initiate 2FA (this will send the OTP to the user's mobile)
                initiateTwoFactorAuthentication(fullDeviceId, authUser);
                
                // Create an OTP validation request for the client
                LoginResponse.OtpValidateRequest otpRequest = new LoginResponse.OtpValidateRequest();
                otpRequest.setOtp(""); // OTP will be provided by the user
                otpRequest.setDeliveryMethod("SMS");
                
                // Return 2FA required response
                return LoginResponse.twoFactorRequired(user, otpRequest);
            }

            // Complete the login process for existing devices
            return completeLoginProcess(fullDeviceId, authUser, httpRequest);
            
        } catch (AuthException e) {
            log.error("Authentication failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during login: {}", e.getMessage(), e);
            throw new AuthException("Login failed due to an unexpected error");
        }
    }

    /**
     * Finds a user by their mobile number.
     *
     * @param mobile The mobile number to search for
     * @return The AuthUser with the specified mobile number
     * @throws AuthException If no user is found with the given mobile number
     */
    private AuthUser findUserByMobile(String mobile) {
        return authUserRepository.findByMobile(mobile)
                .orElseThrow(() -> new AuthException("User not found with mobile number: " + mobile));
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
        log.info("Starting registration for user: {}", request.email());
        
        // Validate password policy
        validatePasswordPolicy(request.password());
        
        // Check if user already exists
        validateEmailUniqueness(request.email());
        
        // Create AuthUser
        AuthUser authUser = createUserFromRequest(request, httpServletRequest);
        log.info("Created AuthUser for: {}", request.email());
        
        // Create User profile
        User userProfile = createUserProfileFromRequest(request, authUser.getId());
        log.info("Created User profile for: {}", request.email());
        
        // Save AuthUser first
        AuthUser savedAuthUser = authUserRepository.save(authUser);
        log.info("Saved AuthUser for: {}", request.email());
        
        // Save User profile
        User savedUserProfile = userRepository.save(userProfile);
        log.info("Saved User profile for: {}", request.email());
        
        return new RegisterResponse(
                savedAuthUser.getId(),
                "device_" + savedAuthUser.getId(), // deviceId
                savedAuthUser.getName(),
                savedAuthUser.getEmail(),
                savedAuthUser.getMobile(),
                "User registered successfully"
        );
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
        
        // Set role based on request
        UserRole role = UserRole.valueOf(request.role());
        log.info("Setting role for user: {} to: {}", request.email(), role);
        user.setRole(role);
        
        // Set address information if available
        if (request.address() != null) {
            AddressInfo addressInfo = new AddressInfo();
            addressInfo.setAddressLine1(request.address().getAddress());
            addressInfo.setPincode(request.address().getPincode());
            addressInfo.setState(request.address().getCityInfo().getState());
            addressInfo.setCountry(request.address().getCityInfo().getCountry());
            addressInfo.setAddressType("HOME"); // Default to HOME
            addressInfo.setIsPrimary(true); // Set as primary address
            addressInfo.setVerified(false); // Not verified initially
            user.setAddressInfo(addressInfo);
        }
        
        // Set other default values as needed
        return user;
    }

    // Helper methods
    void validatePasswordPolicy(String password) {
        if (password == null || password.length() < SecurityConstants.MIN_PASSWORD_LENGTH || password.length() > SecurityConstants.MAX_PASSWORD_LENGTH) {
            throw new AuthException("Password must be between " + SecurityConstants.MIN_PASSWORD_LENGTH + " and " + SecurityConstants.MAX_PASSWORD_LENGTH + " characters");
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

        log.debug("Password validation passed for user");
    }

    private void authenticateUser(String email, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            auth.isAuthenticated();
        } catch (Exception e) {
            throw new AuthException("Authorization unsuccessful.Either email/mobile or password is invalid", e);
        }
    }

    private AuthUser getAuthenticatedUser(String email, String password) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
        return (AuthUser) auth.getPrincipal();
    }

    private void validateIpAccess(AuthUser user, String remoteIp) {
        try {
            List<String> whitelistedIps = null;
            if (user.getSecurityConfiguration() != null) {
                whitelistedIps = (List<String>) user.getSecurityConfiguration().get("allowedIps");
            }
            
            if (!deviceService.isIpAllowed(whitelistedIps, remoteIp)) {
                loginAuditService.sendLoginAlertEmail(
                        user.getEmail(),
                        user.getName(),
                        remoteIp
                );
                throw new AuthException("Access denied from IP: " + remoteIp);
            }
        } catch (Exception e) {
            log.warn("IP validation failed for user {} from IP {}: {}", user.getEmail(), remoteIp, e.getMessage());
            // For now, allow access if IP validation fails to prevent login issues
            // In production, you might want to be more strict
        }
    }

    private String formatDeviceId(String deviceId, UUID userId) {
        return String.format(DEVICE_ID_FORMAT, deviceId, userId);
    }

    private boolean isNewDevice(String fullDeviceId) {
        // Skip device-based 2FA if disabled (e.g., for tests)
        if (!device2faEnabled) {
            return false;
        }
        
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

    private void checkLoginAttempts(AuthUser user) throws AccountLockedException {
        int failedAttempts = user.getSecurityConfigValue("failedAttempts", Integer.class);
        Long lockTime = user.getSecurityConfigValue("lockTime", Long.class);
        
        if (failedAttempts >= SecurityConstants.MAX_LOGIN_ATTEMPTS) {
            if (lockTime == null || System.currentTimeMillis() > lockTime + SecurityConstants.LOCK_TIME_DURATION.toMillis()) {
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

    /**
     * Completes the login process by generating tokens, registering the device, and returning a LoginResponse.
     *
     * @param fullDeviceId The full device ID
     * @param authUser The authenticated user
     * @param request The HTTP request
     * @return LoginResponse containing tokens and user information
     */
    private LoginResponse completeLoginProcess(String fullDeviceId, AuthUser authUser, HttpServletRequest request) {
        try {
            // Generate tokens
            String accessToken = jwtUtil.generateAccessToken(authUser);
            String refreshToken = jwtUtil.generateRefreshToken(authUser);
            
            // Get or create user profile
            User user = userRepository.findByEmail(authUser.getEmail())
                .orElseGet(() -> {
                    // Create a basic user profile if it doesn't exist
                    User newUser = new User();
                    newUser.setEmail(authUser.getEmail());
                    newUser.setName(authUser.getName());
                    return userRepository.save(newUser);
                });
            
            // Extract device metadata and update device information
            try {
                DeviceMetadata deviceMetadata = deviceMetadataExtractor.extractDeviceMetadata(request);
                deviceService.registerDevice(
                    fullDeviceId,
                    authUser,
                    authUser.getSecurityConfiguration(),
                    deviceMetadata
                );
            } catch (Exception e) {
                log.warn("Device registration failed for user {}: {}", authUser.getEmail(), e.getMessage());
                // Continue with login even if device registration fails
            }
            
            // Log successful login
            try {
                loginAuditService.logSuccessfulLogin(
                    authUser.getId().toString(),
                    request.getRemoteAddr()
                );
            } catch (Exception e) {
                log.warn("Failed to log successful login for user {}: {}", authUser.getEmail(), e.getMessage());
            }
            
            // Create and send login alert (optional)
            try {
                LoginAlertRequest alertRequest = LoginAlertRequest.builder()
                    .userId(authUser.getId().toString())
                    .email(user.getEmail())
                    .username(user.getName())
                    .ipAddress(request.getRemoteAddr())
                    .deviceInfo("unknown")
                    .timestamp(LocalDateTime.now())
                    .location("unknown")
                    .suspiciousActivity(false)
                    .build();
                loginAuditService.sendLoginAlert(alertRequest);
            } catch (Exception e) {
                log.warn("Failed to send login alert for user {}: {}", authUser.getEmail(), e.getMessage());
            }
            
            // Return the login response with tokens
            return LoginResponse.success(user, accessToken, refreshToken);
            
        } catch (Exception e) {
            log.error("Login process failed for user {}: {}", authUser.getEmail(), e.getMessage(), e);
            throw new AuthException("Login process failed: " + e.getMessage(), e);
        }
    }

    private OtpLoginResponse createOtpLoginResponse(AuthUser authUser) {
        String accessToken = jwtUtil.generateAccessToken(authUser);
        String refreshToken = jwtUtil.generateRefreshToken(authUser);
        
        // Get the User object from the database
        User user = userRepository.findByEmail(authUser.getEmail())
                .orElseThrow(() -> new RuntimeException("User profile not found for email: " + authUser.getEmail()));
        
        // Check if 2FA is required based on user's security configuration
        Boolean require2fa = (Boolean) authUser.getSecurityConfiguration().get("require2fa");
        Boolean twoDAuthRequired = require2fa != null ? require2fa : false;
        
        OtpLoginResponse response = new OtpLoginResponse();
        response.setSuccess(true);
        response.setMessage("OTP login successful");
        response.setUser(user);
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        response.setTwoDAuthRequired(twoDAuthRequired);
        
        return response;
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
        
        // Set role based on request
        String roleName = "ROLE_" + request.role();
        Role userRole = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Error: Role " + roleName + " is not found."));

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

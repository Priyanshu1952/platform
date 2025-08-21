package com.tj.services.ums.constants;

import java.time.Duration;

/**
 * Security-related constants for the UMS application
 */
public final class SecurityConstants {
    
    // Private constructor to prevent instantiation
    private SecurityConstants() {}
    
    // Authentication constants
    public static final int MAX_LOGIN_ATTEMPTS = 5;
    public static final Duration LOCK_TIME_DURATION = Duration.ofMinutes(15);
    public static final int MAX_OTP_ATTEMPTS = 3;
    public static final Duration OTP_LOCK_TIME_DURATION = Duration.ofMinutes(5);
    
    // Rate limiting constants
    public static final int RATE_LIMIT_LOGIN_PER_MINUTE = 10;
    public static final int RATE_LIMIT_REGISTER_PER_HOUR = 5;
    public static final int RATE_LIMIT_OTP_REQUEST_PER_MINUTE = 10;
    public static final int RATE_LIMIT_PASSWORD_RESET_PER_HOUR = 3;
    public static final int RATE_LIMIT_EMAIL_VERIFICATION_PER_HOUR = 10;
    
    // JWT constants
    public static final String JWT_TOKEN_PREFIX = "Bearer ";
    public static final String JWT_HEADER_NAME = "Authorization";
    public static final String JWT_CLAIM_TYPE_REFRESH = "REFRESH";
    public static final String JWT_CLAIM_EMULATED = "emulated";
    public static final String JWT_CLAIM_EMULATED_BY = "emulated_by";
    public static final String JWT_CLAIM_TARGET_USER_ID = "target_user_id";
    public static final String JWT_CLAIM_TARGET_USER_EMAIL = "target_user_email";
    
    // Password policy constants
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;
    public static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
    
    // OTP constants
    public static final int DEFAULT_OTP_LENGTH = 6;
    public static final int OTP_EXPIRY_MINUTES = 5;
    public static final String TEST_OTP_VALUE = "123456";
    
    // Device constants
    public static final String DEVICE_ID_HEADER = "deviceid";
    public static final String DEVICE_ID_FORMAT = "%s_%s";
    
    // Role constants
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_AGENT = "ROLE_AGENT";
    
    // Error codes
    public static final String ERROR_CODE_AUTH_FAILED = "801";
    public static final String ERROR_CODE_INVALID_OTP = "802";
    public static final String ERROR_CODE_TOKEN_EXPIRED = "803";
    public static final String ERROR_CODE_RATE_LIMIT_EXCEEDED = "804";
    public static final String ERROR_CODE_INVALID_INPUT = "805";
} 
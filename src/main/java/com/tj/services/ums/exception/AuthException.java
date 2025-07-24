package com.tj.services.ums.exception;

import org.springframework.http.HttpStatus;

/**
 * Custom exception class for authentication and authorization related errors.
 * Includes HTTP status codes and error types for proper API error handling.
 */
public class AuthException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final ErrorType errorType;

    public AuthException(String message) {
        this(message, HttpStatus.UNAUTHORIZED, ErrorType.AUTHENTICATION_ERROR);
    }

    public AuthException(String message, HttpStatus httpStatus) {
        this(message, httpStatus, ErrorType.AUTHENTICATION_ERROR);
    }

    public AuthException(String message, HttpStatus httpStatus, ErrorType errorType) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorType = errorType;
    }

    public AuthException(String message, Throwable cause) {
        this(message, cause, HttpStatus.UNAUTHORIZED, ErrorType.AUTHENTICATION_ERROR);
    }

    public AuthException(String message, Throwable cause, HttpStatus httpStatus, ErrorType errorType) {
        super(message, cause);
        this.httpStatus = httpStatus;
        this.errorType = errorType;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public ErrorType getErrorType() {
        return errorType;
    }

    /**
     * Enumeration of different error types for more granular error handling
     */
    public enum ErrorType {
        AUTHENTICATION_ERROR,
        AUTHORIZATION_ERROR,
        ACCOUNT_LOCKED,
        INVALID_CREDENTIALS,
        TOKEN_EXPIRED,
        OTP_VALIDATION_FAILED,
        IP_BLOCKED,
        DEVICE_NOT_REGISTERED
    }
}
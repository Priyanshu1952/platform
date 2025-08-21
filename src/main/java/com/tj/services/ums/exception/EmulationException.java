package com.tj.services.ums.exception;

import org.springframework.http.HttpStatus;

/**
 * Custom exception class for emulation-related errors.
 * Includes HTTP status codes and error types for proper API error handling.
 */
public class EmulationException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final ErrorType errorType;

    public EmulationException(String message) {
        this(message, HttpStatus.FORBIDDEN, ErrorType.EMULATION_ERROR);
    }

    public EmulationException(String message, HttpStatus httpStatus) {
        this(message, httpStatus, ErrorType.EMULATION_ERROR);
    }

    public EmulationException(String message, HttpStatus httpStatus, ErrorType errorType) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorType = errorType;
    }

    public EmulationException(String message, Throwable cause) {
        this(message, cause, HttpStatus.FORBIDDEN, ErrorType.EMULATION_ERROR);
    }

    public EmulationException(String message, Throwable cause, HttpStatus httpStatus, ErrorType errorType) {
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
        EMULATION_ERROR,
        SESSION_EXPIRED,
        INSUFFICIENT_PERMISSIONS,
        SESSION_NOT_FOUND,
        ALREADY_EMULATING,
        USER_NOT_LINKED,
        TARGET_USER_NOT_FOUND
    }
} 
package com.tj.services.ums.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when a requested device is not found in the system.
 * Automatically returns a 404 (NOT_FOUND) status when thrown in a controller.
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class DeviceNotFoundException extends RuntimeException {

    /**
     * Constructs a new exception with a default message.
     */
    public DeviceNotFoundException() {
        super("Device not found");
    }

    /**
     * Constructs a new exception with the specified detail message.
     * @param message the detail message
     */
    public DeviceNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public DeviceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the device ID that wasn't found.
     * @param deviceId the ID of the device that wasn't found
     */
    public DeviceNotFoundException(String deviceId, boolean isFullDeviceId) {
        super(isFullDeviceId
                ? String.format("Device with ID '%s' not found", deviceId)
                : String.format("No device found matching criteria: %s", deviceId));
    }

    /**
     * Constructs a new exception when a device isn't found for a specific user.
     * @param deviceId the device ID
     * @param userId the user ID
     */
    public DeviceNotFoundException(String deviceId, String userId) {
        super(String.format("Device '%s' not found for user '%s'", deviceId, userId));
    }
}
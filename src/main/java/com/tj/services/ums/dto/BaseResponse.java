package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * Base response class that provides common response fields for all API responses.
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BaseResponse {
    private boolean success;
    private String message;
    private String errorCode;
    
    /**
     * Creates a success response with the given message.
     */
    public static BaseResponse success(String message) {
        return new BaseResponse()
                .setSuccess(true)
                .setMessage(message);
    }
    
    /**
     * Creates an error response with the given message and optional error code.
     */
    public static BaseResponse error(String message, String errorCode) {
        return new BaseResponse()
                .setSuccess(false)
                .setMessage(message)
                .setErrorCode(errorCode);
    }
}

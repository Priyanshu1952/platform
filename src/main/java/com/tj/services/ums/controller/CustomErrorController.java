package com.tj.services.ums.controller;

import com.tj.services.ums.exception.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom error controller to handle HTTP errors properly
 * This ensures that 404 errors are returned as 404 instead of 403
 */
@RestController
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<ErrorResponse> handleError(HttpServletRequest request) {
        Object status = request.getAttribute("javax.servlet.error.status_code");
        Object message = request.getAttribute("javax.servlet.error.message");
        Object path = request.getAttribute("javax.servlet.error.request_uri");
        
        int statusCode = status != null ? (Integer) status : 500;
        String errorMessage = message != null ? message.toString() : "An error occurred";
        String requestPath = path != null ? path.toString() : "Unknown";
        
        // Determine error type based on status code
        String errorType;
        switch (statusCode) {
            case 404:
                errorType = "NOT_FOUND";
                errorMessage = "Endpoint not found: " + requestPath;
                break;
            case 403:
                errorType = "FORBIDDEN";
                errorMessage = "Access denied";
                break;
            case 401:
                errorType = "UNAUTHORIZED";
                errorMessage = "Authentication required";
                break;
            case 400:
                errorType = "BAD_REQUEST";
                errorMessage = "Invalid request";
                break;
            default:
                errorType = "INTERNAL_ERROR";
                break;
        }
        
        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(statusCode)
                .error(HttpStatus.valueOf(statusCode).getReasonPhrase())
                .errorType(errorType)
                .message(errorMessage)
                .path(requestPath)
                .build();
        
        return new ResponseEntity<>(errorResponse, HttpStatus.valueOf(statusCode));
    }
} 
package com.tj.services.ums.controller;

import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.dto.AuditLogRequest;
import com.tj.services.ums.dto.AuditLogResponse;
import com.tj.services.ums.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for audit operations
 */
@Slf4j
@RestController
@RequestMapping("/ums/v1")
@RequiredArgsConstructor
@Tag(name = "Audit", description = "Endpoints for audit operations")
@SecurityRequirement(name = "bearerAuth")
public class AuditController {

    private final AuditService auditService;

    /**
     * Fetches audit logs for user data
     */
    @PostMapping("/audits")
    @Operation(summary = "Get audit logs", description = "Fetches audit logs for user data based on filters")
    @PreAuthorize("hasRole('ADMIN') or #request.userId == authentication.principal.username")
    public ResponseEntity<ApiResponse> getAuditLogs(
            @Valid @RequestBody AuditLogRequest request,
            HttpServletRequest httpRequest) {
        
        log.info("Audit logs requested for user: {}", request.userId());
        
        try {
            AuditLogResponse response = auditService.getAuditLogs(request);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(true)
                    .httpStatus(200)
                    .build();
            
            ApiResponse apiResponse = ApiResponse.builder()
                    .status(status)
                    .data(response)
                    .message("Audit logs retrieved successfully")
                    .build();
            
            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            log.error("Error fetching audit logs for user: {}", request.userId(), e);
            
            ApiResponse.Status status = ApiResponse.Status.builder()
                    .success(false)
                    .httpStatus(500)
                    .build();
            
            ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                    .errCode("500")
                    .message("Error fetching audit logs: " + e.getMessage())
                    .build();
            
            ApiResponse apiResponse = ApiResponse.builder()
                    .status(status)
                    .errors(List.of(error))
                    .build();
            
            return ResponseEntity.status(500).body(apiResponse);
        }
    }
} 
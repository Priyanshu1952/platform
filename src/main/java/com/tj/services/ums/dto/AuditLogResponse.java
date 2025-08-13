package com.tj.services.ums.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for audit log responses
 */
public record AuditLogResponse(
    List<AuditLogEntry> auditLogs,
    Integer totalCount,
    Integer page,
    Integer size,
    Boolean hasNext,
    Boolean hasPrevious
) {
    
    /**
     * Individual audit log entry
     */
    public record AuditLogEntry(
        Long id,
        String userId,
        String actionType,
        String description,
        String ipAddress,
        String userAgent,
        LocalDateTime timestamp,
        String sessionId,
        String result,
        String errorMessage
    ) {}
} 
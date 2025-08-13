package com.tj.services.ums.service;

import com.tj.services.ums.dto.AuditLogRequest;
import com.tj.services.ums.dto.AuditLogResponse;

/**
 * Service interface for audit operations
 */
public interface AuditService {
    
    /**
     * Fetch audit logs for user data based on filters
     */
    AuditLogResponse getAuditLogs(AuditLogRequest request);
    
    /**
     * Log an audit event
     */
    void logAuditEvent(String userId, String actionType, String description, String ipAddress, String userAgent, String result);
    
    /**
     * Log an audit event with error
     */
    void logAuditEventWithError(String userId, String actionType, String description, String ipAddress, String userAgent, String errorMessage);
} 
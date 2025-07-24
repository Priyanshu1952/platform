package com.tj.services.ums.service;

import com.tj.services.ums.dto.AuditLogEntry;
import com.tj.services.ums.dto.LoginAlertRequest;

public interface LoginAuditService {
    void sendLoginAlert(LoginAlertRequest request);
    void sendLoginAlertEmail(String email, String username, String ipAddress);
    void logSecurityEvent(AuditLogEntry entry);
    void logFailedLoginAttempt(String userId, String ipAddress, String reason);
    void logSuccessfulLogin(String userId, String ipAddress);
}
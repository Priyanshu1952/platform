package com.tj.services.ums.service;

import com.tj.services.ums.model.EmulationAuditLog;
import com.tj.services.ums.model.EmulationSession;
import com.tj.services.ums.model.User;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface EmulationService {
    // Session Management
    EmulationSession startEmulation(UUID emulatingUserId, UUID targetUserId, String reason, String ipAddress);
    void endEmulation(UUID sessionId, UUID emulatingUserId);
    EmulationSession getActiveSession(UUID emulatingUserId);
    
    // Linked User Validation
    boolean canEmulateUser(UUID emulatingUserId, UUID targetUserId);
    List<User> getLinkedUsers(UUID emulatingUserId);
    
    // JWT Token Generation
    String generateEmulatedAccessToken(User targetUser, UUID emulatingUserId);
    
    // Audit Logging
    void logEmulationAction(UUID sessionId, String actionType, Map<String, Object> details);
    List<EmulationAuditLog> getEmulationAuditLogs(UUID sessionId);
    
    // Session Validation
    boolean isSessionValid(UUID sessionId);
    boolean isEmulationActive(UUID emulatingUserId);
} 
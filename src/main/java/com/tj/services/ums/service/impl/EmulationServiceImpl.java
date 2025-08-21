package com.tj.services.ums.service.impl;

import com.tj.services.ums.exception.EmulationException;
import com.tj.services.ums.model.*;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.EmulationAuditLogRepository;
import com.tj.services.ums.repository.EmulationSessionRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.EmulationService;
import com.tj.services.ums.service.UserService;
import com.tj.services.ums.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
@Slf4j
@RequiredArgsConstructor
public class EmulationServiceImpl implements EmulationService {
    
    private final EmulationSessionRepository sessionRepository;
    private final EmulationAuditLogRepository auditLogRepository;
    private final AuthUserRepository authUserRepository;
    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtUtil jwtUtil;
    
    @Override
    public EmulationSession startEmulation(UUID emulatingUserId, UUID targetUserId, String reason, String ipAddress) {
        // Validate that target user is linked to emulating user
        if (!canEmulateUser(emulatingUserId, targetUserId)) {
            throw new EmulationException("Target user is not linked to your account");
        }
        
        // Check for existing active session
        if (isEmulationActive(emulatingUserId)) {
            throw new EmulationException("You already have an active emulation session");
        }
        
        // Create session
        EmulationSession session = EmulationSession.builder()
                .emulatingUserId(emulatingUserId)
                .targetUserId(targetUserId)
                .sessionToken(generateSessionToken())
                .startTime(LocalDateTime.now())
                .status(EmulationStatus.ACTIVE)
                .reason(reason)
                .ipAddress(ipAddress)
                .build();
        
        session = sessionRepository.save(session);
        
        // Log the action
        logEmulationAction(session.getId(), EmulationActionType.SESSION_START.name(), 
                Map.of("reason", reason, "ipAddress", ipAddress));
        
        return session;
    }
    
    @Override
    public void endEmulation(UUID sessionId, UUID emulatingUserId) {
        EmulationSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new EmulationException("Session not found"));
        
        if (!session.getEmulatingUserId().equals(emulatingUserId)) {
            throw new EmulationException("Unauthorized to end this session");
        }
        
        session.setEndTime(LocalDateTime.now());
        session.setStatus(EmulationStatus.TERMINATED);
        sessionRepository.save(session);
        
        logEmulationAction(sessionId, EmulationActionType.SESSION_END.name(), 
                Map.of("endedBy", emulatingUserId.toString()));
    }
    
    @Override
    public EmulationSession getActiveSession(UUID emulatingUserId) {
        return sessionRepository.findActiveSessionByEmulatingUserId(emulatingUserId).orElse(null);
    }
    
    @Override
    public boolean canEmulateUser(UUID emulatingUserId, UUID targetUserId) {
        // Get linked users for the emulating user
        List<User> linkedUsers = getLinkedUsers(emulatingUserId);
        
        // Check if target user is in the linked users list
        return linkedUsers.stream()
                .anyMatch(user -> user.getId().equals(targetUserId));
    }
    
    @Override
    public List<User> getLinkedUsers(UUID emulatingUserId) {
        // Get the user by UUID and then get their linked users
        AuthUser authUser = authUserRepository.findById(emulatingUserId)
                .orElseThrow(() -> new EmulationException("User not found"));
        
        User user = userRepository.findByEmail(authUser.getEmail())
                .orElseThrow(() -> new EmulationException("User profile not found"));
        
        return userService.getUserRelations(user.getUserId());
    }
    
    @Override
    public String generateEmulatedAccessToken(User targetUser, UUID emulatingUserId) {
        return jwtUtil.generateEmulatedAccessToken(targetUser, emulatingUserId);
    }
    
    @Override
    public void logEmulationAction(UUID sessionId, String actionType, Map<String, Object> details) {
        try {
            EmulationSession session = sessionRepository.findById(sessionId).orElse(null);
            if (session != null) {
                EmulationAuditLog auditLog = EmulationAuditLog.builder()
                        .emulationSessionId(sessionId)
                        .emulatingUserId(session.getEmulatingUserId())
                        .targetUserId(session.getTargetUserId())
                        .actionType(actionType)
                        .actionDetails(details)
                        .timestamp(LocalDateTime.now())
                        .success(true)
                        .build();
                
                auditLogRepository.save(auditLog);
            }
        } catch (Exception e) {
            log.error("Failed to log emulation action", e);
        }
    }
    
    @Override
    public List<EmulationAuditLog> getEmulationAuditLogs(UUID sessionId) {
        return auditLogRepository.findByEmulationSessionId(sessionId);
    }
    
    @Override
    public boolean isSessionValid(UUID sessionId) {
        EmulationSession session = sessionRepository.findById(sessionId).orElse(null);
        return session != null && session.getStatus() == EmulationStatus.ACTIVE;
    }
    
    @Override
    public boolean isEmulationActive(UUID emulatingUserId) {
        return sessionRepository.findActiveSessionByEmulatingUserId(emulatingUserId).isPresent();
    }
    
    private String generateSessionToken() {
        return UUID.randomUUID().toString() + "_" + System.currentTimeMillis();
    }
} 
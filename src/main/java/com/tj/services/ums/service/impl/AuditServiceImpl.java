package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.AuditLogRequest;
import com.tj.services.ums.dto.AuditLogResponse;
import com.tj.services.ums.model.AuditLogEntity;
import com.tj.services.ums.repository.AuditLogRepository;
import com.tj.services.ums.service.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuditServiceImpl implements AuditService {

    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public AuditLogResponse getAuditLogs(AuditLogRequest request) {
        log.info("Fetching audit logs for user: {}", request.userId());
        
        // Create pageable with sorting
        Sort sort = Sort.by(Sort.Direction.fromString(
            request.sortOrder() != null ? request.sortOrder() : "DESC"), "timestamp");
        
        Pageable pageable = PageRequest.of(
            request.page() != null ? request.page() : 0,
            request.size() != null ? request.size() : 20,
            sort
        );
        
        // Fetch audit logs with filters
        Page<AuditLogEntity> auditLogPage = auditLogRepository.findByUserIdAndFilters(
            request.userId(),
            request.actionType(),
            request.startDate(),
            request.endDate(),
            request.ipAddress(),
            pageable
        );
        
        // Convert to DTOs
        List<AuditLogResponse.AuditLogEntry> auditLogs = auditLogPage.getContent().stream()
            .map(this::convertToAuditLogEntry)
            .collect(Collectors.toList());
        
        return new AuditLogResponse(
            auditLogs,
            (int) auditLogPage.getTotalElements(),
            auditLogPage.getNumber(),
            auditLogPage.getSize(),
            auditLogPage.hasNext(),
            auditLogPage.hasPrevious()
        );
    }

    @Override
    public void logAuditEvent(String userId, String actionType, String description, 
                            String ipAddress, String userAgent, String result) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userAgent", userAgent);
            metadata.put("result", result);
            metadata.put("description", description);
            
            AuditLogEntity auditLog = AuditLogEntity.builder()
                .userId(userId)
                .eventType(actionType)
                .ipAddress(ipAddress)
                .success("SUCCESS".equals(result))
                .details(description)
                .metadata(metadata)
                .build();
            
            auditLogRepository.save(auditLog);
            log.debug("Audit event logged for user: {}, action: {}", userId, actionType);
        } catch (Exception e) {
            log.error("Failed to log audit event for user: {}, action: {}", userId, actionType, e);
        }
    }

    @Override
    public void logAuditEventWithError(String userId, String actionType, String description, 
                                     String ipAddress, String userAgent, String errorMessage) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userAgent", userAgent);
            metadata.put("errorMessage", errorMessage);
            metadata.put("description", description);
            
            AuditLogEntity auditLog = AuditLogEntity.builder()
                .userId(userId)
                .eventType(actionType)
                .ipAddress(ipAddress)
                .success(false)
                .details(description)
                .metadata(metadata)
                .build();
            
            auditLogRepository.save(auditLog);
            log.debug("Audit event with error logged for user: {}, action: {}", userId, actionType);
        } catch (Exception e) {
            log.error("Failed to log audit event with error for user: {}, action: {}", userId, actionType, e);
        }
    }

    private AuditLogResponse.AuditLogEntry convertToAuditLogEntry(AuditLogEntity entity) {
        String userAgent = null;
        String result = null;
        String errorMessage = null;
        
        if (entity.getMetadata() != null) {
            userAgent = (String) entity.getMetadata().get("userAgent");
            result = (String) entity.getMetadata().get("result");
            errorMessage = (String) entity.getMetadata().get("errorMessage");
        }
        
        return new AuditLogResponse.AuditLogEntry(
            entity.getId().getMostSignificantBits(), // Convert UUID to Long for compatibility
            entity.getUserId(),
            entity.getEventType(),
            entity.getDetails(),
            entity.getIpAddress(),
            userAgent,
            entity.getTimestamp(),
            entity.getDeviceId(), // Use deviceId as sessionId
            result != null ? result : (entity.isSuccess() ? "SUCCESS" : "FAILED"),
            errorMessage
        );
    }
} 
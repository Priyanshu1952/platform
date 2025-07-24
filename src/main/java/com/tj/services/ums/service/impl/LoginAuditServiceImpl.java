package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.AuditLogEntry;
import com.tj.services.ums.dto.LoginAlertRequest;
import com.tj.services.ums.model.AuditLogEntity;
import com.tj.services.ums.repository.AuditLogRepository;
import com.tj.services.ums.service.GeoLocationService;
import com.tj.services.ums.service.LoginAuditService;
import com.tj.services.ums.service.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAuditServiceImpl implements LoginAuditService {

    private final NotificationService notificationService;
    private final GeoLocationService geoLocationService;
    private final AuditLogRepository auditLogRepository;

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Async
    @Override
    public void sendLoginAlert(LoginAlertRequest request) {
        try {
            notificationService.sendSecurityAlertEmail(
                    request.email(),
                    "Suspicious Login Attempt",
                    buildAlertMessage(request)
            );
            logSecurityEvent(AuditLogEntry.builder()
                    .eventType("SECURITY_ALERT")
                    .userId(request.userId())
                    .ipAddress(request.ipAddress())
                    .timestamp(LocalDateTime.now())
                    .success(false)
                    .details("Suspicious login attempt detected")
                    .build());
        } catch (Exception e) {
            log.error("Failed to send login alert", e);
        }
    }

    @Async
    @Override
    public void sendLoginAlertEmail(String email, String username, String ipAddress) {
        try {
            String location = String.valueOf(geoLocationService.getLocationFromIp(ipAddress));
            String timestamp = LocalDateTime.now().format(DATE_FORMAT);

            String subject = "Suspicious Login Attempt Alert";
            String message = String.format(
                    "Dear %s,\n\n" +
                            "We detected a login attempt from an unauthorized IP address:\n\n" +
                            "• Time: %s\n" +
                            "• IP Address: %s\n" +
                            "• Location: %s\n\n" +
                            "If this wasn't you, please secure your account immediately.\n\n" +
                            "Best regards,\n" +
                            "Security Team",
                    username,
                    timestamp,
                    ipAddress,
                    location
            );

            notificationService.sendEmail(email, subject, message);
            log.warn("Sent login alert email to {} for IP {}", email, ipAddress);

        } catch (Exception e) {
            log.error("Failed to send login alert email to {} for IP {}", email, ipAddress, e);
            // Consider adding a retry mechanism or dead letter queue here
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Override
    public void logSecurityEvent(AuditLogEntry entry) {
        try {
            auditLogRepository.save(convertToEntity(entry));
        } catch (Exception e) {
            log.error("Failed to log security event", e);
        }
    }

    @Async
    @Override
    public void logFailedLoginAttempt(String userId, String ipAddress, String reason) {
        String location = String.valueOf(geoLocationService.getLocationFromIp(ipAddress));
        logSecurityEvent(AuditLogEntry.builder()
                .eventType("LOGIN_FAILED")
                .userId(userId)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now())
                .success(false)
                .details(String.format("Failed login attempt from %s. Reason: %s", location, reason))
                .build());
    }

    @Async
    @Override
    public void logSuccessfulLogin(String userId, String ipAddress) {
        String location = String.valueOf(geoLocationService.getLocationFromIp(ipAddress));
        logSecurityEvent(AuditLogEntry.builder()
                .eventType("LOGIN_SUCCESS")
                .userId(userId)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now())
                .success(true)
                .details(String.format("Successful login from %s", location))
                .build());
    }

    private String buildAlertMessage(LoginAlertRequest request) {
        return String.format(
                "Suspicious login attempt detected:\n\n" +
                        "User: %s (%s)\n" +
                        "Time: %s\n" +
                        "IP Address: %s\n" +
                        "Location: %s\n" +
                        "Device: %s\n\n" +
                        "This action was %striggered by suspicious activity.",
                request.username(),
                request.email(),
                request.timestamp(),
                request.ipAddress(),
                request.location(),
                request.deviceInfo(),
                request.suspiciousActivity() ? "" : "not ");
    }

    private AuditLogEntity convertToEntity(AuditLogEntry entry) {
        return AuditLogEntity.builder()
                .eventType(entry.eventType())
                .userId(entry.userId())
                .ipAddress(entry.ipAddress())
                .timestamp(entry.timestamp())
                .success(entry.success())
                .details(entry.details())
                .build();
    }
}
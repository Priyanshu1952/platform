package com.tj.services.ums.dto;

import com.tj.services.ums.model.EmulationSession;
import com.tj.services.ums.model.EmulationStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmulationSessionResponse {
    private UUID id;
    private UUID emulatingUserId;
    private String emulatingUserName;
    private UUID targetUserId;
    private String targetUserName;
    private String sessionToken;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private EmulationStatus status;
    private String reason;
    private String ipAddress;
    private Long durationMinutes;
    
    public static EmulationSessionResponse from(EmulationSession session) {
        return EmulationSessionResponse.builder()
                .id(session.getId())
                .emulatingUserId(session.getEmulatingUserId())
                .targetUserId(session.getTargetUserId())
                .sessionToken(session.getSessionToken())
                .startTime(session.getStartTime())
                .endTime(session.getEndTime())
                .status(session.getStatus())
                .reason(session.getReason())
                .ipAddress(session.getIpAddress())
                .durationMinutes(calculateDuration(session))
                .build();
    }
    
    private static Long calculateDuration(EmulationSession session) {
        if (session.getEndTime() != null) {
            return Duration.between(session.getStartTime(), session.getEndTime()).toMinutes();
        }
        return Duration.between(session.getStartTime(), LocalDateTime.now()).toMinutes();
    }
} 
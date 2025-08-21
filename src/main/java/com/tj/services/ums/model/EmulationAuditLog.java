package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "emulation_audit_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmulationAuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(name = "emulation_session_id")
    private UUID emulationSessionId;
    
    @Column(name = "emulating_user_id", nullable = false)
    private UUID emulatingUserId;
    
    @Column(name = "target_user_id", nullable = false)
    private UUID targetUserId;
    
    @Column(name = "action_type", nullable = false)
    private String actionType;
    
    @Column(name = "action_details", columnDefinition = "JSONB")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> actionDetails;
    
    @Column(name = "ip_address")
    private String ipAddress;
    
    @Column(nullable = false)
    private LocalDateTime timestamp;
    
    @Column(nullable = false)
    private Boolean success;
    
    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;
} 
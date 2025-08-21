package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "emulation_sessions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmulationSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(name = "emulating_user_id", nullable = false)
    private UUID emulatingUserId;
    
    @Column(name = "target_user_id", nullable = false)
    private UUID targetUserId;
    
    @Column(name = "session_token", nullable = false)
    private String sessionToken;
    
    @Column(name = "start_time", nullable = false)
    private LocalDateTime startTime;
    
    @Column(name = "end_time")
    private LocalDateTime endTime;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EmulationStatus status;
    
    @Column(columnDefinition = "TEXT")
    private String reason;
    
    @Column(name = "ip_address")
    private String ipAddress;
    
    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;
    
    @CreationTimestamp
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
} 
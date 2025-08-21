package com.tj.services.ums.repository;

import com.tj.services.ums.model.EmulationSession;
import com.tj.services.ums.model.EmulationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmulationSessionRepository extends JpaRepository<EmulationSession, UUID> {
    
    @Query("SELECT es FROM EmulationSession es WHERE es.emulatingUserId = :emulatingUserId AND es.status = 'ACTIVE'")
    Optional<EmulationSession> findActiveSessionByEmulatingUserId(@Param("emulatingUserId") UUID emulatingUserId);
    
    @Query("SELECT es FROM EmulationSession es WHERE es.sessionToken = :sessionToken")
    Optional<EmulationSession> findBySessionToken(@Param("sessionToken") String sessionToken);
    
    @Query("SELECT es FROM EmulationSession es WHERE es.status = 'ACTIVE'")
    List<EmulationSession> findAllActiveSessions();
    
    @Query("SELECT es FROM EmulationSession es WHERE es.targetUserId = :targetUserId")
    List<EmulationSession> findByTargetUserId(@Param("targetUserId") UUID targetUserId);
    
    @Query("SELECT es FROM EmulationSession es WHERE es.emulatingUserId = :emulatingUserId")
    List<EmulationSession> findByEmulatingUserId(@Param("emulatingUserId") UUID emulatingUserId);
    
    @Query("SELECT es FROM EmulationSession es WHERE es.endTime IS NULL AND es.startTime < :expiryTime")
    List<EmulationSession> findExpiredSessions(@Param("expiryTime") LocalDateTime expiryTime);
    
    @Query("SELECT es FROM EmulationSession es WHERE es.emulatingUserId = :emulatingUserId AND es.status = :status")
    List<EmulationSession> findByEmulatingUserIdAndStatus(@Param("emulatingUserId") UUID emulatingUserId, @Param("status") EmulationStatus status);
} 
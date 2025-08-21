package com.tj.services.ums.repository;

import com.tj.services.ums.model.EmulationAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface EmulationAuditLogRepository extends JpaRepository<EmulationAuditLog, UUID> {
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.emulationSessionId = :sessionId ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findByEmulationSessionId(@Param("sessionId") UUID sessionId);
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.emulatingUserId = :emulatingUserId ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findByEmulatingUserId(@Param("emulatingUserId") UUID emulatingUserId);
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.targetUserId = :targetUserId ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findByTargetUserId(@Param("targetUserId") UUID targetUserId);
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.timestamp BETWEEN :startTime AND :endTime ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findByTimestampBetween(
            @Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime
    );
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.actionType = :actionType ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findByActionType(@Param("actionType") String actionType);
    
    @Query("SELECT eal FROM EmulationAuditLog eal WHERE eal.success = :success ORDER BY eal.timestamp DESC")
    List<EmulationAuditLog> findBySuccess(@Param("success") Boolean success);
} 
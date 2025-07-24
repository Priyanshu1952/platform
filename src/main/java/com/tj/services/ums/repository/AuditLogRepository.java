package com.tj.services.ums.repository;

import com.tj.services.ums.model.AuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {
    // Custom queries if needed
}
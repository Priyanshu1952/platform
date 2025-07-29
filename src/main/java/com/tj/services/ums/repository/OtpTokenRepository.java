package com.tj.services.ums.repository;

import com.tj.services.ums.model.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {

    Optional<OtpToken> findByDeviceIdAndConsumedFalseAndExpiresAtAfter(String deviceId, Instant currentTime);

    @Transactional
    @Modifying
    @Query("DELETE FROM OtpToken t WHERE t.expiresAt <= :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    @Transactional
    @Modifying
    @Query("UPDATE OtpToken t SET t.consumed = true WHERE t.deviceId = :deviceId")
    void markAsConsumed(@Param("deviceId") String deviceId);

    @Transactional
    @Modifying
    @Query("UPDATE OtpToken t SET t.attempts = t.attempts + 1 WHERE t.deviceId = :deviceId")
    void incrementAttempts(@Param("deviceId") String deviceId);
}

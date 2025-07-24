package com.tj.services.ums.dto;

import java.time.Instant;
import java.util.Date;

public record TokenRefreshResponse(
        String message,
        String accessToken,
        String refreshToken,
        Date expiresAt
) {}
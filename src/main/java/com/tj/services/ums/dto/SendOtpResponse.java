package com.tj.services.ums.dto;

import com.tj.services.ums.model.OtpType;

import java.time.Instant;

public record SendOtpResponse(
        String message,
        String deviceId,
        Instant expiresAt,
        OtpType otpType
) {
}

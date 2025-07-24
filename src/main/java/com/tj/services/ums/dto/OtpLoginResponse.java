package com.tj.services.ums.dto;

public record OtpLoginResponse(
        String token,
        String refreshToken,
        java.time.Instant expiresIn
) {}

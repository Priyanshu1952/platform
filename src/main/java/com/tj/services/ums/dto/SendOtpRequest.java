package com.tj.services.ums.dto;

import com.tj.services.ums.model.OtpType;

import java.time.Instant;

public record SendOtpRequest(
        String deviceId,
        String mobile,
        String email,
        OtpType otpType
) {
}

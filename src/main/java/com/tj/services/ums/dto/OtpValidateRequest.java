package com.tj.services.ums.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OtpValidateRequest {
    private String otp;
    private String deviceId;
    private String email;
    private String mobile;
} 
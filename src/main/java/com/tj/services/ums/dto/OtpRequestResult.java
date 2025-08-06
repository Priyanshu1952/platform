package com.tj.services.ums.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OtpRequestResult {
    private boolean success;
    private String message;
    private String transactionId; // For tracking OTP session
    private int statusCode;
}

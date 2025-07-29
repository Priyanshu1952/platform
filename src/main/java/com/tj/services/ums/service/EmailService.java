package com.tj.services.ums.service;

public interface EmailService {
    void sendOtp(String email, String otp, int expiryMinutes);
}

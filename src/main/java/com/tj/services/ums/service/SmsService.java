package com.tj.services.ums.service;

public interface SmsService {
    void sendOtp(String mobile, String otp, int expiryMinutes);
}
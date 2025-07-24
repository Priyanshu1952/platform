package com.tj.services.ums.service;

public interface EmailVerificationService {
    void sendVerificationEmail(String email);
    void verifyEmail(String token);
}
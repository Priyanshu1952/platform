package com.tj.services.ums.service;

public interface NotificationService {
    void sendSecurityAlertEmail(String to, String subject, String message);
    void sendEmail(String to, String subject, String message);

    void sendMail(String to, String subject, String body, boolean isHtml);

    void sendMail(String to, String subject, String body);
}
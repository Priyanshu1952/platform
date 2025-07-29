package com.tj.services.ums.service.impl;

import com.tj.services.ums.exception.EmailDeliveryException;
import com.tj.services.ums.service.EmailService;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromEmail;

    @Autowired
    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendOtp(String email, String otp, int expiryMinutes) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Your One-Time Password (OTP) for UMS");

            String htmlContent = buildOtpEmailContent(otp, expiryMinutes);
            helper.setText(htmlContent, true);

            mailSender.send(mimeMessage);
            logger.info("Successfully sent OTP email to {}", email);
        } catch (Exception e) {
            logger.error("Failed to send OTP email to {}: {}", email, e.getMessage(), e);
            throw new EmailDeliveryException("Failed to send OTP email", e);
        }
    }

    private String buildOtpEmailContent(String otp, int expiryMinutes) {
        return String.format("""
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Your UMS OTP</title>
            </head>
            <body style="font-family: Arial, sans-serif; margin: 20px; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h2 style="color: #333;">Your One-Time Password (OTP)</h2>
                <p>Please use the following OTP to complete your action. This OTP is valid for %d minutes.</p>
                <div style="font-size: 24px; font-weight: bold; color: #2a2a2a; background-color: #f0f0f0; padding: 10px; border-radius: 5px; text-align: center;">
                    %s
                </div>
                <p style="margin-top: 20px;">If you did not request this OTP, please disregard this email.</p>
            </body>
            </html>
            """, expiryMinutes, otp);
    }
}

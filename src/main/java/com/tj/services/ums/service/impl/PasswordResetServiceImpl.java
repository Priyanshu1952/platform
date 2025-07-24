package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.PasswordResetRequest;
import com.tj.services.ums.exception.AuthException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class PasswordResetServiceImpl implements PasswordResetService {

    private final AuthUserRepository authUserRepository;
    private final JavaMailSender mailSender;
    private final PasswordEncoder passwordEncoder;
    private final AuthServiceImpl authService;

    @Override
    public void createPasswordResetToken(String email) {
        AuthUser user = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("User not found with email: " + email));

        String token = UUID.randomUUID().toString();
        user.getSecurityConfiguration().put("passwordResetToken", token);
        user.getSecurityConfiguration().put("passwordResetTokenExpiry", System.currentTimeMillis() + 3600000); // 1 hour expiry
        authUserRepository.save(user);

        sendPasswordResetEmail(user.getEmail(), token);
    }

    @Override
    public void resetPassword(PasswordResetRequest request) {
        AuthUser user = authUserRepository.findByEmail(request.email())
                .orElseThrow(() -> new AuthException("User not found with email: " + request.email()));

        String storedToken = (String) user.getSecurityConfiguration().get("passwordResetToken");
        Long tokenExpiry = (Long) user.getSecurityConfiguration().get("passwordResetTokenExpiry");

        if (storedToken == null || !storedToken.equals(request.token()) || tokenExpiry == null || tokenExpiry < System.currentTimeMillis()) {
            throw new AuthException("Invalid or expired password reset token");
        }

        authService.validatePasswordPolicy(request.newPassword());

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        user.getSecurityConfiguration().remove("passwordResetToken");
        user.getSecurityConfiguration().remove("passwordResetTokenExpiry");
        authUserRepository.save(user);
    }

    private void sendPasswordResetEmail(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("noreply@yourdomain.com"); // This should be configured in application.properties
        message.setTo(email);
        message.setSubject("Password Reset Request");
        // Assuming a frontend URL for password reset, replace with actual URL
        String resetUrl = "http://your-frontend-app/reset-password?token=" + token + "&email=" + email;
        message.setText("To reset your password, please click on the following link: " + resetUrl + "\n\nThis token is valid for 1 hour.");
        mailSender.send(message);
    }
}
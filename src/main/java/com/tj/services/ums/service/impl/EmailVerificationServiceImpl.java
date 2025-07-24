package com.tj.services.ums.service.impl;

import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.service.EmailVerificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailVerificationServiceImpl implements EmailVerificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationServiceImpl.class);

    private final AuthUserRepository authUserRepository;
    private final JavaMailSender mailSender;

    @Autowired
    public EmailVerificationServiceImpl(AuthUserRepository authUserRepository, JavaMailSender mailSender) {
        this.authUserRepository = authUserRepository;
        this.mailSender = mailSender;
    }

    @Override
    @Async
    public void sendVerificationEmail(String email) {
        log.info("Sending verification email to: {}", email);
        AuthUser user = authUserRepository.findByEmail(email).orElse(null);
        if (user != null) {
            String token = UUID.randomUUID().toString();
            user.setVerificationToken(token);
            authUserRepository.save(user);

            String verificationLink = "http://localhost:8085/verify-email?token=" + token;
            MimeMessage message = mailSender.createMimeMessage();
            try {
                MimeMessageHelper helper = new MimeMessageHelper(message, true);
                helper.setTo(email);
                helper.setSubject("Email Verification");
                helper.setText("Click the link to verify your email: " + verificationLink);
                mailSender.send(message);
                log.info("Verification email sent to: {}", email);
            } catch (MessagingException e) {
                log.error("Error sending verification email to: {}", email, e);
            }
        }
    }

    @Override
    public void verifyEmail(String token) {
        AuthUser user = authUserRepository.findByVerificationToken(token).orElse(null);
        if (user != null) {
            user.setEmailVerified(true);
            user.setVerificationToken(null);
            authUserRepository.save(user);
        }
    }
}
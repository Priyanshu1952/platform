package com.tj.services.ums.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class ConfigurationValidator {

    @Value("${jwt.secret:}")
    private String jwtSecret;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    @Value("${textbelt.api-key:}")
    private String textbeltApiKey;

    @Value("${surepass.api.token:}")
    private String surepassApiToken;

    @EventListener(ApplicationReadyEvent.class)
    public void validateConfiguration() {
        List<String> missingConfigs = new ArrayList<>();

        // Check for required environment variables
        if (jwtSecret.isEmpty() || jwtSecret.equals("${JWT_SECRET}")) {
            missingConfigs.add("JWT_SECRET");
        }

        if (mailPassword.isEmpty() || mailPassword.equals("${MAIL_PASSWORD}")) {
            missingConfigs.add("MAIL_PASSWORD");
        }

        if (textbeltApiKey.isEmpty() || textbeltApiKey.equals("${TEXTBELT_API_KEY}")) {
            missingConfigs.add("TEXTBELT_API_KEY");
        }

        if (surepassApiToken.isEmpty() || surepassApiToken.equals("${SUREPASS_API_TOKEN}")) {
            missingConfigs.add("SUREPASS_API_TOKEN");
        }

        if (!missingConfigs.isEmpty()) {
            log.error("Missing required environment variables: {}", missingConfigs);
            log.error("Please set the following environment variables:");
            missingConfigs.forEach(config -> log.error("  - {}", config));
            
            // In production, you might want to fail fast
            if (isProductionEnvironment()) {
                throw new IllegalStateException("Missing required configuration: " + missingConfigs);
            } else {
                log.warn("Application will start with limited functionality due to missing configuration");
            }
        } else {
            log.info("All required configuration variables are set");
        }
    }

    private boolean isProductionEnvironment() {
        String activeProfile = System.getProperty("spring.profiles.active");
        return "prod".equals(activeProfile) || "production".equals(activeProfile);
    }
} 
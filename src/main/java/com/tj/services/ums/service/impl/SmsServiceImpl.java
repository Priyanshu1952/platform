package com.tj.services.ums.service.impl;

import com.tj.services.ums.exception.SmsDeliveryException;
import com.tj.services.ums.service.SmsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class SmsServiceImpl implements SmsService {

    private static final Logger logger = LoggerFactory.getLogger(SmsServiceImpl.class);

    @Value("${app.sms.provider.url}")
    private String smsProviderUrl;

    @Value("${textbelt.api-key}")
    private String apiKey;

    @Autowired
    private final RestTemplate restTemplate;

    @Autowired
    public SmsServiceImpl(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public void sendOtp(String mobile, String otp, int expiryMinutes) {
        try {
            String message = String.format(
                    "Your OTP for UMS is: %s. It will expire in %d minutes.",
                    otp,
                    expiryMinutes
            );

            sendSms(mobile, message);
        } catch (Exception e) {
            throw new SmsDeliveryException("Error while sending OTP SMS", e);
        }
    }

    private void sendSms(String mobile, String message) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        String requestBody = String.format("{\"key\":\"%s\",\"text\":\"%s\",\"user\":\"phone\",\"number\":\"%s\"}", apiKey, message, mobile);

        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(smsProviderUrl, entity, String.class);

            logger.info("TextBelt raw response for {}: {}", mobile, response.getBody());

            try {
                JsonNode json = new ObjectMapper().readTree(response.getBody());
                boolean success = json.has("success") && json.get("success").asBoolean();
                String error = json.has("error") ? json.get("error").asText() : null;
                logger.info("TextBelt parsed response for {}: success={}, error={}", mobile, success, error);
            } catch (Exception parseEx) {
                logger.warn("Failed to parse TextBelt response JSON for {}: {}", mobile, parseEx.getMessage());
            }

            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Successfully sent SMS to {}", mobile);
            } else {
                logger.error("Failed to send SMS. Status: {}, Body: {}", response.getStatusCode(), response.getBody());
                throw new SmsDeliveryException("Failed to send SMS: " + response.getBody());
            }
        } catch (Exception e) {
            logger.error("Error sending SMS to {}: {}", mobile, e.getMessage(), e);
            throw new SmsDeliveryException("SMS delivery failed", e);
        }
    }
}

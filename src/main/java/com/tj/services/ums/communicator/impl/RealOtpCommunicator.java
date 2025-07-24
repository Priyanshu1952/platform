package com.tj.services.ums.communicator.impl;

import com.tj.services.ums.communicator.OTPCommunicator;
import com.tj.services.ums.model.OtpToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Component
@Service
public class RealOtpCommunicator implements OTPCommunicator {

    @Value("${textbelt.api-url}")
    private String apiUrl;

    @Value("${textbelt.api-key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();

    public boolean sendOtp(String phoneNumber, String otp) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("phone", phoneNumber);
        payload.put("message", "Your OTP is: " + otp);
        payload.put("key", apiKey);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(apiUrl, request, String.class);
            System.out.println("Textbelt response: " + response.getBody());
            return response.getStatusCode() == HttpStatus.OK && response.getBody().contains("\"success\":true");
        } catch (Exception e) {
            System.err.println("Failed to send SMS: " + e.getMessage());
            return false;
        }
    }

    @Override
    public OtpToken validateOtp(String deviceId, String otp, int expirySeconds) {
        return null;
    }

    @Override
    public void generateOtp(OtpToken otpToken) {

    }

    @Override
    public void updateConsumedOtp(String deviceId) {

    }
}

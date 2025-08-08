package com.tj.services.ums.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tj.services.ums.dto.KycVerificationRequest;
import com.tj.services.ums.dto.KycVerificationResponse;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.service.KycService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class KycServiceImpl implements KycService {

    private final AuthUserRepository authUserRepository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final String apiToken;
    private final String panEndpoint;
    private final String aadhaarEndpoint;

    public KycServiceImpl(
            AuthUserRepository authUserRepository, 
            ObjectMapper objectMapper,
            @Value("${surepass.api.url}") String surepassApiUrl,
            @Value("${surepass.api.token}") String apiToken,
            @Value("${surepass.api.pan.endpoint}") String panEndpoint,
            @Value("${surepass.api.aadhaar.endpoint}") String aadhaarEndpoint) {
        this.authUserRepository = authUserRepository;
        this.objectMapper = objectMapper;
        this.apiToken = apiToken;
        this.panEndpoint = panEndpoint;
        this.aadhaarEndpoint = aadhaarEndpoint;
        this.webClient = WebClient.builder()
                .baseUrl(surepassApiUrl)
                .defaultHeader("Authorization", "Bearer " + apiToken)
                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    @Override
    public KycVerificationResponse verifyPan(String userId, KycVerificationRequest request) {
        log.info("Initiating PAN verification for user: {} with PAN: {}", userId, request.getPanNumber());
        
        if (!request.isPanNumber()) {
            log.warn("Invalid PAN format provided for user: {}", userId);
            return createErrorResponse(400, "Invalid PAN number format");
        }

        try {
            Map<String, String> requestBody = Map.of("id_number", request.getPanNumber());
            log.debug("Sending PAN verification request to Surepass: {}", requestBody);
            
            KycVerificationResponse response = makeKycApiCall(panEndpoint, requestBody)
                    .timeout(Duration.ofSeconds(30))
                    .block();

            return processVerificationResponse(userId, response, "PAN", 
                    KycVerificationResponse.PanVerificationData.class,
                    user -> {
                        user.setPanVerified(true);
                        return user;
                    });

        } catch (Exception e) {
            log.error("Error during PAN verification for user: {}", userId, e);
            return handleVerificationException(e, "PAN");
        }
    }

    @Override
    public KycVerificationResponse verifyAadhaar(String userId, KycVerificationRequest request) {
        log.info("Initiating Aadhaar verification for user: {} with Aadhaar: {}", userId, request.getAadhaarNumber());
        
        if (!request.isAadhaarNumber()) {
            log.warn("Invalid Aadhaar format provided for user: {}", userId);
            return createErrorResponse(400, "Invalid Aadhaar number format");
        }

        try {
            Map<String, String> requestBody = Map.of("aadhaar_number", request.getAadhaarNumber());
            log.debug("Sending Aadhaar verification request to Surepass: {}", requestBody);
            
            KycVerificationResponse response = makeKycApiCall(aadhaarEndpoint, requestBody)
                    .timeout(Duration.ofSeconds(30))
                    .block();

            return processVerificationResponse(userId, response, "Aadhaar", 
                    KycVerificationResponse.AadhaarVerificationData.class,
                    user -> {
                        user.setAadhaarVerified(true);
                        return user;
                    });

        } catch (Exception e) {
            log.error("Error during Aadhaar verification for user: {}", userId, e);
            return handleVerificationException(e, "Aadhaar");
        }
    }

    private Mono<KycVerificationResponse> makeKycApiCall(String endpoint, Map<String, String> requestBody) {
        return webClient.post()
                .uri(endpoint)
                .bodyValue(requestBody)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(), 
                    clientResponse -> clientResponse.bodyToMono(String.class)
                        .map(errorBody -> {
                            log.error("Surepass API Error Response: {} - {}", clientResponse.statusCode(), errorBody);
                            if (clientResponse.statusCode().value() == 422) {
                                return new IllegalArgumentException("Invalid document: " + errorBody);
                            }
                            return new RuntimeException("Surepass API Error: " + clientResponse.statusCode() + " - " + errorBody);
                        }))
                .bodyToMono(KycVerificationResponse.class);
    }

    private <T> KycVerificationResponse processVerificationResponse(
            String userId, 
            KycVerificationResponse response, 
            String documentType,
            Class<T> dataClass,
            java.util.function.Function<AuthUser, AuthUser> userUpdater) {
        
        if (response == null || response.getStatusCode() != 200 || response.getData() == null) {
            log.warn("{} verification failed for user: {}. Status: {}, Message: {}", 
                    documentType, userId, 
                    response != null ? response.getStatusCode() : "null", 
                    response != null ? response.getMessage() : "null");
            return createErrorResponse(400, documentType + " verification failed: " + 
                    (response != null ? response.getMessage() : "Invalid response from verification service"));
        }

        try {
            T verificationData = objectMapper.convertValue(response.getData(), dataClass);
            String fullName = extractFullName(verificationData);
            
            if (fullName == null) {
                log.warn("{} verification returned null name for user: {}", documentType, userId);
                return createErrorResponse(400, documentType + " verification failed: No name found in response");
            }

            Optional<AuthUser> userOptional = authUserRepository.findByEmail(userId);
            if (userOptional.isEmpty()) {
                log.warn("User not found with email: {}", userId);
                return createErrorResponse(404, "User not found with email: " + userId);
            }

            AuthUser user = userOptional.get();
            String userNameFromDb = (user.getFirstName() + " " + user.getLastName()).trim();
            String documentNameFromApi = fullName.trim();

            log.debug("Comparing names for user: {} - DB: '{}', API: '{}'", userId, userNameFromDb, documentNameFromApi);

            if (isNameMatching(userNameFromDb, documentNameFromApi)) {
                AuthUser updatedUser = userUpdater.apply(user);
                authUserRepository.save(updatedUser);
                log.info("{} verification successful and name matched for user: {}", documentType, userId);
                
                KycVerificationResponse successResponse = new KycVerificationResponse();
                successResponse.setStatusCode(200);
                successResponse.setMessage(documentType + " verification successful and name matched.");
                successResponse.setData(verificationData);
                return successResponse;
            } else {
                log.warn("{} name mismatch for user: {}. DB: '{}', API: '{}'", 
                        documentType, userId, userNameFromDb, documentNameFromApi);
                return createErrorResponse(400, 
                        "Verification failed: The name on the " + documentType + " does not match our records.");
            }
        } catch (Exception e) {
            log.error("Error processing {} verification response for user: {}", documentType, userId, e);
            return createErrorResponse(500, "Error processing " + documentType + " verification response");
        }
    }

    private String extractFullName(Object verificationData) {
        if (verificationData instanceof KycVerificationResponse.PanVerificationData panData) {
            return panData.getFullName();
        } else if (verificationData instanceof KycVerificationResponse.AadhaarVerificationData aadhaarData) {
            return aadhaarData.getFullName();
        }
        return null;
    }

    private boolean isNameMatching(String dbName, String apiName) {
        if (dbName == null || apiName == null) {
            return false;
        }
        
        // Simple case-insensitive comparison - can be enhanced with fuzzy matching
        String normalizedDbName = dbName.toLowerCase().replaceAll("\\s+", " ");
        String normalizedApiName = apiName.toLowerCase().replaceAll("\\s+", " ");
        
        return normalizedDbName.equals(normalizedApiName);
    }

    private KycVerificationResponse handleVerificationException(Exception e, String documentType) {
        if (e instanceof IllegalArgumentException) {
            log.warn("Invalid {} provided: {}", documentType, e.getMessage());
            return createErrorResponse(422, "Invalid " + documentType + " number provided: The " + 
                    documentType + " number format is incorrect or does not exist in the government database.");
        } else {
            log.error("Unexpected error during {} verification", documentType, e);
            return createErrorResponse(500, "Failed to verify " + documentType + 
                    " due to an external service error: " + e.getMessage());
        }
    }

    private KycVerificationResponse createErrorResponse(int statusCode, String message) {
        KycVerificationResponse errorResponse = new KycVerificationResponse();
        errorResponse.setStatusCode(statusCode);
        errorResponse.setMessage(message);
        return errorResponse;
    }
}

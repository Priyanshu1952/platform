package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.KycVerificationRequest;
import com.tj.services.ums.dto.KycVerificationResponse;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.service.KycService;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class KycServiceImpl implements KycService {

    private final AuthUserRepository authUserRepository;

    private final WebClient webClient;

    @Value("${surepass.api.token}")
    private String apiToken;

    @Value("${surepass.api.pan.endpoint}")
    private String panEndpoint;

    @Value("${surepass.api.aadhaar.endpoint}")
    private String aadhaarEndpoint;

    public KycServiceImpl(AuthUserRepository authUserRepository, @Value("${surepass.api.url}") String surepassApiUrl) {
        this.authUserRepository = authUserRepository;
        this.webClient = WebClient.builder().baseUrl(surepassApiUrl).build();
    }

    // Using Spring's WebClient for modern, non-blocking API calls
    // @Autowired
    // private WebClient.Builder webClientBuilder;

    // @Value("${kyc.provider.api.url}")
    // private String kycApiUrl;

    @Override
    public KycVerificationResponse verifyPan(String userId, KycVerificationRequest request) {
        System.out.println("Initiating PAN verification for user: " + userId + " with PAN: " + request.getPanNumber());

        try {
            System.out.println("Sending request to Surepass: " + Map.of("id_number", request.getPanNumber()));
            
            // Make API call to Surepass PAN verification endpoint
            KycVerificationResponse response = webClient.post()
                    .uri(panEndpoint) // Surepass PAN advanced verification endpoint
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .bodyValue(Map.of("id_number", request.getPanNumber()))
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(), 
                        clientResponse -> clientResponse.bodyToMono(String.class)
                            .map(errorBody -> {
                                System.err.println("Surepass API Error Response: " + errorBody);
                                // For 422, this is a business logic error (invalid PAN), not a system error
                                if (clientResponse.statusCode().value() == 422) {
                                    return new IllegalArgumentException("Invalid PAN: " + errorBody);
                                }
                                return new RuntimeException("Surepass API Error: " + clientResponse.statusCode() + " - " + errorBody);
                            }))
                    .bodyToMono(KycVerificationResponse.class)
                    .block(); // Using .block() for simplicity, consider async handling in production

            // Check if API call was successful (status code 200 typically means success)
            if (response != null && response.getStatusCode() == 200 && response.getData() != null && response.getData().getFullName() != null) {
                return authUserRepository.findByEmail(userId).map(user -> {
                    String userNameFromDb = (user.getFirstName() + " " + user.getLastName()).trim();
                    String panNameFromApi = response.getData().getFullName().trim();

                    System.out.println("Comparing names - DB: '" + userNameFromDb + "', API: '" + panNameFromApi + "'");

                    if (userNameFromDb.equalsIgnoreCase(panNameFromApi)) {
                        user.setPanVerified(true);
                        authUserRepository.save(user);
                        System.out.println("PAN verification successful and name matched for user: " + userId);
                        
                        // Create success response
                        KycVerificationResponse successResponse = new KycVerificationResponse();
                        successResponse.setStatusCode(200);
                        successResponse.setMessage("PAN verification successful and name matched.");
                        successResponse.setData(response.getData());
                        return successResponse;
                    } else {
                        System.out.println("PAN name mismatch for user: " + userId + ". DB: '" + userNameFromDb + "', API: '" + panNameFromApi + "'");
                        
                        // Create failure response for name mismatch
                        KycVerificationResponse failureResponse = new KycVerificationResponse();
                        failureResponse.setStatusCode(400);
                        failureResponse.setMessage("Verification failed: The name on the PAN card does not match our records.");
                        return failureResponse;
                    }
                }).orElse(createErrorResponse(404, "User not found with email: " + userId));
            } else {
                System.err.println("PAN verification failed. Status: " + (response != null ? response.getStatusCode() : "null") + ", Message: " + (response != null ? response.getMessage() : "null"));
                return createErrorResponse(400, "PAN verification failed: " + (response != null ? response.getMessage() : "Invalid response from verification service"));
            }

        } catch (IllegalArgumentException e) {
            // Handle 422 Invalid PAN as a business logic error, not a system error
            System.err.println("Invalid PAN provided: " + e.getMessage());
            return createErrorResponse(422, "Invalid PAN number provided: The PAN number format is incorrect or does not exist in the government database.");
        } catch (Exception e) {
            System.err.println("Error during PAN verification: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse(500, "Failed to verify PAN due to an external service error: " + e.getMessage());
        }
    }

    @Override
    public KycVerificationResponse verifyAadhaar(String userId, KycVerificationRequest request) {
        System.out.println("Initiating Aadhaar verification for user: " + userId + " with Aadhaar: " + request.getAadhaarNumber());

        try {
            // Make API call to Surepass Aadhaar verification endpoint
            KycVerificationResponse response = webClient.post()
                    .uri(aadhaarEndpoint) // Surepass Aadhaar verification endpoint
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .body(Mono.just(request), KycVerificationRequest.class)
                    .retrieve()
                    .bodyToMono(KycVerificationResponse.class)
                    .block(); // Using .block() for simplicity, consider async handling in production

            // Check if API call was successful (status code 200 typically means success)
            if (response != null && response.getStatusCode() == 200 && response.getData() != null && response.getData().getFullName() != null) {
                return authUserRepository.findByEmail(userId).map(user -> {
                    String userNameFromDb = (user.getFirstName() + " " + user.getLastName()).trim();
                    String aadhaarNameFromApi = response.getData().getFullName().trim();

                    System.out.println("Comparing names - DB: '" + userNameFromDb + "', API: '" + aadhaarNameFromApi + "'");

                    if (userNameFromDb.equalsIgnoreCase(aadhaarNameFromApi)) {
                        user.setAadhaarVerified(true);
                        authUserRepository.save(user);
                        System.out.println("Aadhaar verification successful and name matched for user: " + userId);
                        
                        // Create success response
                        KycVerificationResponse successResponse = new KycVerificationResponse();
                        successResponse.setStatusCode(200);
                        successResponse.setMessage("Aadhaar verification successful and name matched.");
                        successResponse.setData(response.getData());
                        return successResponse;
                    } else {
                        System.out.println("Aadhaar name mismatch for user: " + userId + ". DB: '" + userNameFromDb + "', API: '" + aadhaarNameFromApi + "'");
                        
                        // Create failure response for name mismatch
                        KycVerificationResponse failureResponse = new KycVerificationResponse();
                        failureResponse.setStatusCode(400);
                        failureResponse.setMessage("Verification failed: The name on the Aadhaar card does not match our records.");
                        return failureResponse;
                    }
                }).orElse(createErrorResponse(404, "User not found with email: " + userId));
            } else {
                System.err.println("Aadhaar verification failed. Status: " + (response != null ? response.getStatusCode() : "null") + ", Message: " + (response != null ? response.getMessage() : "null"));
                return createErrorResponse(400, "Aadhaar verification failed: " + (response != null ? response.getMessage() : "Invalid response from verification service"));
            }

        } catch (Exception e) {
            System.err.println("Error during Aadhaar verification: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse(500, "Failed to verify Aadhaar due to an external service error: " + e.getMessage());
        }
    }

    private KycVerificationResponse createErrorResponse(int statusCode, String message) {
        KycVerificationResponse errorResponse = new KycVerificationResponse();
        errorResponse.setStatusCode(statusCode);
        errorResponse.setMessage(message);
        return errorResponse;
    }
}

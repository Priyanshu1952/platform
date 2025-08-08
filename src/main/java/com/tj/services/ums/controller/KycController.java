package com.tj.services.ums.controller;

import com.tj.services.ums.dto.KycVerificationRequest;
import com.tj.services.ums.dto.KycVerificationResponse;
import com.tj.services.ums.service.KycService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/kyc")
public class KycController {

    private final KycService kycService;

    public KycController(KycService kycService) {
        this.kycService = kycService;
    }

    @PostMapping("/pan")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<KycVerificationResponse> verifyPan(
            @Valid @RequestBody KycVerificationRequest request, 
            Authentication authentication) {
        String userId = authentication.getName();
        KycVerificationResponse response = kycService.verifyPan(userId, request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/aadhaar")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<KycVerificationResponse> verifyAadhaar(
            @Valid @RequestBody KycVerificationRequest request, 
            Authentication authentication) {
        String userId = authentication.getName();
        KycVerificationResponse response = kycService.verifyAadhaar(userId, request);
        return ResponseEntity.ok(response);
    }
}

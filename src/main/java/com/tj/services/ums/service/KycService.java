package com.tj.services.ums.service;

import com.tj.services.ums.dto.KycVerificationRequest;
import com.tj.services.ums.dto.KycVerificationResponse;

public interface KycService {
    KycVerificationResponse verifyPan(String userId, KycVerificationRequest request);
    KycVerificationResponse verifyAadhaar(String userId, KycVerificationRequest request);
}

package com.tj.services.ums.service;

import com.tj.services.ums.communicator.OTPCommunicator;
import com.tj.services.ums.exception.InvalidOtpException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.OtpToken;
import com.tj.services.ums.repository.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OTPCommunicator otpCommunicator;
    private final AuthUserRepository authUserRepository;

    public boolean validateOtp(String deviceId, String otp, AuthUser user) {
        OtpToken token = otpCommunicator.validateOtp(deviceId, otp, 50);
        if (token == null ||
                !token.getMobile().equals(user.getMobile()) ||
                !token.getEmail().equals(user.getEmail())) {
            throw new InvalidOtpException("Invalid OTP for user " + user.getEmail());
        }
        otpCommunicator.updateConsumedOtp(deviceId);
        return true;
    }

    public void sendOtp(String deviceId, String mobile, String email) {
        otpCommunicator.generateOtp(
                OtpToken.builder()
                        .requestId(deviceId)
                        .type("SIGNIN_OTP")
                        .mobile(mobile)
                        .email(email)
                        .build()
        );
    }
}
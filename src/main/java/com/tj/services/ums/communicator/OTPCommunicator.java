package com.tj.services.ums.communicator;

import com.tj.services.ums.model.OtpToken;

public interface OTPCommunicator {
    OtpToken validateOtp(String deviceId, String otp, int expirySeconds);
    void generateOtp(OtpToken otpToken);
    void updateConsumedOtp(String deviceId);
}
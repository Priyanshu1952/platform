package com.tj.services.ums.communicator.impl;

import com.tj.services.ums.communicator.OTPCommunicator;
import com.tj.services.ums.model.OtpToken;
import org.springframework.stereotype.Service;

@Service
public class RealOtpCommunicator implements OTPCommunicator {

    @Override
    public boolean sendOtp(String phoneNumber, String otp) {
        // This method is no longer used for sending OTPs directly.
        // OTP sending is handled by SmsService.
        return false;
    }

    @Override
    public OtpToken validateOtp(String deviceId, String otp, int expirySeconds) {
        // This method should be implemented to validate the OTP
        // For now, it returns null
        return null;
    }

    @Override
    public void generateOtp(OtpToken otpToken) {
        // This method should be implemented to generate and send the OTP
    }

    @Override
    public void updateConsumedOtp(String deviceId) {
        // This method should be implemented to update the consumed status of the OTP
    }
}

package com.tj.services.ums.service;

import com.tj.services.ums.dto.PasswordResetRequest;
import com.tj.services.ums.dto.PasswordResetTokenRequest;

public interface PasswordResetService {
    void createPasswordResetToken(String email);
    void resetPassword(PasswordResetRequest request);
}
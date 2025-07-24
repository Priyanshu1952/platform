package com.tj.services.ums.service;

import com.tj.services.ums.dto.*;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.transaction.annotation.Transactional;

public interface AuthService {

    /**
     * Authenticates a user with the provided login request.
     *
     * @param request the login request containing user credentials
     * @return a response containing authentication tokens and metadata
     */

    @Transactional
    RegisterResponse register(RegisterRequest request, HttpServletRequest httpServletRequest);

    LoginResponse login(LoginRequest request, HttpServletRequest httpRequest);

    OtpLoginResponse otpLogin(OtpLoginRequest request, HttpServletRequest httpRequest);

    TokenRefreshResponse refreshToken(TokenRefreshRequest request);

    void logout(HttpServletRequest request);

    // Additional methods for password reset, email verification, etc. can be added here
}

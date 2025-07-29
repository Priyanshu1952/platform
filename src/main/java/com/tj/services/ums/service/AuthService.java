package com.tj.services.ums.service;

import com.tj.services.ums.dto.*;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.transaction.annotation.Transactional;

public interface AuthService {

    /**
     * Sends an OTP to the user's email for login.
     * @param request contains email and deviceId
     * @return SendOtpResponse with status
     */
    SendOtpResponse sendOtpToEmail(com.tj.services.ums.dto.EmailOtpRequest request);

    /**
     * Authenticates a user with email and OTP.
     * @param request contains email, otp, deviceId
     * @param httpRequest the HTTP request
     * @return OtpLoginResponse if successful
     */
    OtpLoginResponse emailOtpLogin(com.tj.services.ums.dto.EmailOtpLoginRequest request, jakarta.servlet.http.HttpServletRequest httpRequest);


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

    /**
     * Verifies a user's email using the provided verification token.
     *
     * @param token the verification token sent to the user's email
     * @return true if the email was successfully verified, false otherwise
     */
    boolean verifyEmail(String token);
}

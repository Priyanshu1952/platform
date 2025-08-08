package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * Response object for sign-in operations.
 * Matches the structure of the monolith's SignInResponse for compatibility.
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse extends BaseResponse {
    
    private User user;
    private String accessToken;
    private String refreshToken;

    @JsonProperty("2dreq")
    private Boolean twoFactorRequired;

    // Excluded from JSON serialization
    @com.fasterxml.jackson.annotation.JsonIgnore
    private OtpValidateRequest otpValidateRequest;

    /**
     * Factory method for successful login with tokens
     */
    public static LoginResponse success(User user, String accessToken, String refreshToken) {
        LoginResponse response = LoginResponse.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .twoFactorRequired(false)
                .build();
        response.setSuccess(true);
        response.setMessage("Login successful");
        return response;
    }

    /**
     * Factory method for 2FA required case
     */
    public static LoginResponse twoFactorRequired(User user, OtpValidateRequest otpValidateRequest) {
        LoginResponse response = LoginResponse.builder()
                .user(user)
                .twoFactorRequired(true)
                .otpValidateRequest(otpValidateRequest)
                .build();
        response.setSuccess(true);
        response.setMessage("Two-factor authentication required");
        return response;
    }

    /**
     * Nested class for OTP validation request
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OtpValidateRequest {
        private String otp;
        private String deliveryMethod; // e.g., "SMS", "EMAIL"
    }
}
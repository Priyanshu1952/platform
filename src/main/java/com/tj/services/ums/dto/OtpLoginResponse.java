package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tj.services.ums.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class OtpLoginResponse extends BaseResponse {
    private User user;
    private String accessToken;
    private String refreshToken;

    @JsonProperty("2dreq")
    private Boolean twoDAuthRequired;

    @JsonIgnore
    private OtpValidateRequest otpValidateRequest;
}

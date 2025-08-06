package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KycVerificationResponse {

    @JsonProperty("status_code")
    private int statusCode;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private SurepassPanData data;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class SurepassPanData {
        @JsonProperty("full_name")
        private String fullName;
    }
}

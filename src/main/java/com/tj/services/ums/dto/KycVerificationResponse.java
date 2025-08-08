package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KycVerificationResponse {

    @JsonProperty("status_code")
    private int statusCode;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private Object data;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class PanVerificationData {
        @JsonProperty("full_name")
        private String fullName;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AadhaarVerificationData {
        @JsonProperty("full_name")
        private String fullName;
        
        @JsonProperty("aadhaar_number")
        private String aadhaarNumber;
        
        @JsonProperty("date_of_birth")
        private String dateOfBirth;
        
        @JsonProperty("gender")
        private String gender;
        
        @JsonProperty("address")
        private String address;
    }
}

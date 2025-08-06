package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KycVerificationRequest {
    @JsonProperty("id_number")
    @NotBlank(message = "ID number is required")
    @Size(min = 5, max = 20, message = "ID number must be between 5 and 20 characters")
    private String idNumber; // Can be PAN or Aadhaar number
    
    // Convenience getters for backward compatibility
    public String getPanNumber() {
        return idNumber;
    }
    
    public void setPanNumber(String panNumber) {
        this.idNumber = panNumber;
    }
    
    public String getAadhaarNumber() {
        return idNumber;
    }
    
    public void setAadhaarNumber(String aadhaarNumber) {
        this.idNumber = aadhaarNumber;
    }
}

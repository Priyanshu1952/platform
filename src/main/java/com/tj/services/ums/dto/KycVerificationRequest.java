package com.tj.services.ums.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KycVerificationRequest {
    
    @JsonProperty("id_number")
    @NotBlank(message = "ID number is required")
    @Pattern(
        regexp = "^([A-Z]{5}[0-9]{4}[A-Z]{1}|[0-9]{12})$",
        message = "ID number must be a valid PAN (10 characters: 5 letters, 4 digits, 1 letter) or Aadhaar (12 digits)"
    )
    private String idNumber;
    
    // Convenience getters for backward compatibility with specific validation
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
    
    // Helper methods to determine document type
    public boolean isPanNumber() {
        return idNumber != null && idNumber.matches("^[A-Z]{5}[0-9]{4}[A-Z]{1}$");
    }
    
    public boolean isAadhaarNumber() {
        return idNumber != null && idNumber.matches("^[0-9]{12}$");
    }
}

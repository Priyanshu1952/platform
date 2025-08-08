package com.tj.services.ums.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AddressRequest {
    
    @NotBlank(message = "Pincode is required")
    private String pincode;
    
    @NotBlank(message = "Address is required")
    private String address;
    
    @Valid
    @NotNull(message = "City information is required")
    private CityInfoRequest cityInfo;
    
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CityInfoRequest {
        @NotBlank(message = "State is required")
        private String state;
        
        @NotBlank(message = "Country is required")
        private String country;
    }
} 
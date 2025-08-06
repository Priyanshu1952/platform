package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AddressInfo {
    private String addressLine1;
    private String addressLine2;
    private String city;
    private String state;
    private String pincode;
    private String country;
    private String district;
    private String landmark;
    private String addressType; // HOME, OFFICE, BILLING, SHIPPING
    private Boolean isPrimary;
    private Boolean verified;
}

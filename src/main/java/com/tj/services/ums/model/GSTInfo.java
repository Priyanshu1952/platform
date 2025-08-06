package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GSTInfo {
    private String gstNumber;
    private String businessName;
    private String businessType;
    private String registrationDate;
    private String status;
    private String state;
    private String address;
    private Boolean verified;
}

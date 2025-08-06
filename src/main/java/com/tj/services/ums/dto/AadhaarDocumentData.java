package com.tj.services.ums.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AadhaarDocumentData {
    private String aadhaarNumber;
    private String fullName;
    private String dateOfBirth;
    private String gender;
    private String address;
    private String pincode;
    private String state;
    private String district;
    private String mobileNumber; // If available in document
    private String emailAddress; // If available in document
    private String fatherName; // If available
    private String photoBase64; // Extracted photo as base64 string
}

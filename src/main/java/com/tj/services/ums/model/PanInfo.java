package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PanInfo {
    private String panNumber;
    private String fullName;
    private String fatherName;
    private String dateOfBirth;
    private String category;
    private String panStatus;
    private String aadhaarSeedingStatus;
    private String lastUpdated;
    private Boolean verified;
}

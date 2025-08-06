package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserProfile {
    private String firstName;
    private String lastName;
    private String middleName;
    private String displayName;
    private String gender;
    private LocalDate dateOfBirth;
    private String nationality;
    private String profilePicture;
    private String bio;
    private String designation;
    private String department;
    private String reportingManager;
    private LocalDate joiningDate;
    private String workLocation;
    private String emergencyContactName;
    private String emergencyContactNumber;
    private String bloodGroup;
}

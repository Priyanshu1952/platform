package com.tj.services.ums.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Embeddable
@AllArgsConstructor
@NoArgsConstructor
public class ContactPersonInfo {
    private String name;
    private String designation;
    private String email;
    private String mobile;
    private String phone;
    private String department;
    private Boolean isPrimary;
}

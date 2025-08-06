package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserAdditionalInfo {
    private String companyName;
    private String businessType;
    private String industry;
    private String website;
    private String description;
    private LocalDateTime lastLoginDate;
    private String lastLoginIp;
    private Integer loginAttempts;
    private Boolean twoFactorEnabled;
    private String preferredLanguage;
    private String timezone;
    private Map<String, Object> customFields;
    private String referralCode;
    private String referredBy;
}

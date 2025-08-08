package com.tj.services.ums.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
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
    
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> customFields;
    
    private String referralCode;
    private String referredBy;
}

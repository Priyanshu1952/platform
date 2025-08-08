package com.tj.services.ums.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserConfiguration {
    private String configId;
    private String userId;
    
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> settings;
    
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Boolean> permissions;
    
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, String> preferences;
    
    private Boolean notificationsEnabled;
    private Boolean emailNotifications;
    private Boolean smsNotifications;
    private String theme;
    private String language;
    private String dateFormat;
    private String timeFormat;
    private String currency;
}

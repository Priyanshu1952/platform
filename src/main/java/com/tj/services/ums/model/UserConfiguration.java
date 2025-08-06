package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserConfiguration {
    private String configId;
    private String userId;
    private Map<String, Object> settings;
    private Map<String, Boolean> permissions;
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

package com.tj.services.ums.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class OtpToken {
    private String requestId;
    private String type;
    private String key;
    private String mobile;
    private String email;
    // Add other fields as needed
}
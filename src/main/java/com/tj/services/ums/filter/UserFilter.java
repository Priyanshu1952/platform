package com.tj.services.ums.filter;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class UserFilter extends BaseFilter {
    private String email;
    private String mobile;
    private String role;
    private String status;
    private LocalDateTime createdFrom;
    private LocalDateTime createdTo;
} 
package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetails {
    private String userId;
    private String name;
    private String email;
    private String mobile;
    private UserRole role;
    private UserStatus status;
    private String relationshipType; // LINKED, PARENT, CHILD, PARTNER
    private Boolean active;
}

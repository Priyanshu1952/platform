package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.ArrayList;

@Entity
@Table(name = "auth_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class AuthUser implements UserDetails {

    public String getFirstName() {
        // Assuming 'name' is the full name, split to get the first name
        if (name != null && !name.isEmpty()) {
            return name.split(" ")[0];
        }
        return "";
    }

    public String getLastName() {
        // Assuming 'name' is the full name, split to get the last name
        if (name != null && !name.isEmpty()) {
            String[] names = name.split(" ");
            if (names.length > 1) {
                return names[names.length - 1];
            }
        }
        return "";
    }

    public Boolean isEmailVerified() {
        return this.emailVerified;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String mobile;

    @Builder.Default
    private boolean active = true;

    @Builder.Default
    private Boolean emailVerified = false;

    @Column(name = "pan_verified", nullable = true)
    @Builder.Default
    private Boolean panVerified = false;

    @Column(name = "aadhaar_verified", nullable = true)
    @Builder.Default
    private Boolean aadhaarVerified = false;

    private String verificationToken;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    // Security Configuration - Individual columns instead of JSON
    @Column(name = "require_2fa")
    @Builder.Default
    private Boolean require2fa = false;
    
    @Column(name = "device_limit")
    @Builder.Default
    private Integer deviceLimit = 5;
    
    @Column(name = "account_locked")
    @Builder.Default
    private Boolean accountLocked = false;
    
    @Column(name = "failed_attempts")
    @Builder.Default
    private Integer failedAttempts = 0;
    
    @Column(name = "lock_time")
    private Long lockTime;
    
    @Column(name = "last_password_change")
    @Builder.Default
    private Long lastPasswordChange = System.currentTimeMillis();
    
    @Column(name = "password_reset_token")
    private String passwordResetToken;
    
    @Column(name = "password_reset_token_expiry")
    private Long passwordResetTokenExpiry;
    
    // Store allowed IPs as comma-separated string
    @Column(name = "allowed_ips", columnDefinition = "TEXT")
    @Builder.Default
    private String allowedIps = "";

    // ------------ UserDetails Interface Methods ------------ //
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.active && this.emailVerified;
    }

    // Helper methods for security configuration
    public Map<String, Object> getSecurityConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("require2fa", this.require2fa);
        config.put("deviceLimit", this.deviceLimit);
        config.put("accountLocked", this.accountLocked);
        config.put("failedAttempts", this.failedAttempts);
        config.put("lockTime", this.lockTime);
        config.put("lastPasswordChange", this.lastPasswordChange);
        config.put("passwordResetToken", this.passwordResetToken);
        config.put("passwordResetTokenExpiry", this.passwordResetTokenExpiry);
        config.put("allowedIps", parseAllowedIps());
        return config;
    }

    public void setSecurityConfiguration(Map<String, Object> config) {
        if (config != null) {
            this.require2fa = (Boolean) config.getOrDefault("require2fa", false);
            this.deviceLimit = (Integer) config.getOrDefault("deviceLimit", 5);
            this.accountLocked = (Boolean) config.getOrDefault("accountLocked", false);
            this.failedAttempts = (Integer) config.getOrDefault("failedAttempts", 0);
            this.lockTime = (Long) config.getOrDefault("lockTime", null);
            this.lastPasswordChange = (Long) config.getOrDefault("lastPasswordChange", System.currentTimeMillis());
            this.passwordResetToken = (String) config.getOrDefault("passwordResetToken", null);
            this.passwordResetTokenExpiry = (Long) config.getOrDefault("passwordResetTokenExpiry", null);
            this.allowedIps = serializeAllowedIps((List<String>) config.getOrDefault("allowedIps", new ArrayList<>()));
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T getSecurityConfigValue(String key, Class<T> type) {
        switch (key) {
            case "require2fa":
                return (T) this.require2fa;
            case "deviceLimit":
                return (T) this.deviceLimit;
            case "accountLocked":
                return (T) this.accountLocked;
            case "failedAttempts":
                return (T) this.failedAttempts;
            case "lockTime":
                return (T) this.lockTime;
            case "lastPasswordChange":
                return (T) this.lastPasswordChange;
            case "passwordResetToken":
                return (T) this.passwordResetToken;
            case "passwordResetTokenExpiry":
                return (T) this.passwordResetTokenExpiry;
            case "allowedIps":
                return (T) parseAllowedIps();
            default:
                return null;
        }
    }

    // Helper method for common security checks
    public boolean isIpAllowed(String ipAddress) {
        List<String> allowedIpList = parseAllowedIps();
        return allowedIpList.contains(ipAddress);
    }

    // Helper methods for IP list serialization/deserialization
    private List<String> parseAllowedIps() {
        if (this.allowedIps == null || this.allowedIps.isEmpty()) {
            return new ArrayList<>();
        }
        return Arrays.asList(this.allowedIps.split(","));
    }

    private String serializeAllowedIps(List<String> ipList) {
        if (ipList == null || ipList.isEmpty()) {
            return "";
        }
        return String.join(",", ipList);
    }


}
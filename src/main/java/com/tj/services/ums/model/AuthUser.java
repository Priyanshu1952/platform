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

    // Security Configuration (JSON storage)
    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Builder.Default
    private Map<String, Object> securityConfiguration = new HashMap<>();

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
        return !this.getSecurityConfigValue("accountLocked", Boolean.class);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.active && this.emailVerified;
    }

    public Map<String, Object> getSecurityConfiguration() {
        if (this.securityConfiguration == null) {
            this.securityConfiguration = getDefaultSecurityConfig();
        }
        return this.securityConfiguration;
    }

    private Map<String, Object> getDefaultSecurityConfig() {
        return Map.of(
                "require2fa", false,
                "allowedIps", Collections.emptyList(),
                "deviceLimit", 5,
                "accountLocked", false,
                "failedAttempts", 0,
                "lastPasswordChange", System.currentTimeMillis()
        );
    }

    @SuppressWarnings("unchecked")
    public <T> T getSecurityConfigValue(String key, Class<T> type) {
        Object value = getSecurityConfiguration().get(key);
        try {
            return type.cast(value);
        } catch (ClassCastException e) {
            return (T) getDefaultSecurityConfig().get(key);
        }
    }

    // Helper method for common security checks
    public boolean isIpAllowed(String ipAddress) {
        return this.getSecurityConfigValue("allowedIps", List.class)
                .contains(ipAddress);
    }


}
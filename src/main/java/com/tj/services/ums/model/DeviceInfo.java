package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.Map;

@Entity
@Table(name = "device_info", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"fullDeviceId"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String fullDeviceId;

    @Column(nullable = false)
    private String deviceType;
    private String deviceName;

    private String osName;
    private String osVersion;
    private String browserName;
    private String browserVersion;
    private String userAgent;

    private String ipAddress;
    private String country;
    private String region;
    private String city;

    @Column(nullable = false)
    private LocalDateTime lastLoginTime;
    private LocalDateTime firstLoginTime;
    private LocalDateTime lastOtpSent;
    private LocalDateTime trustExpiry;

    @Column(nullable = false)
    private boolean trusted;
    private Double trustScore;
    private int loginCount;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @Transient
    private Object securityConfiguration;

    // Helper methods
    public boolean isTrustedDevice() {
        return this.trusted && (trustExpiry == null || trustExpiry.isAfter(LocalDateTime.now()));
    }

    public String getLocation() {
        return String.format("%s, %s, %s", city, region, country);
    }

    public void updateLocation(String country, String region, String city) {
        this.country = country;
        this.region = region;
        this.city = city;
    }
}
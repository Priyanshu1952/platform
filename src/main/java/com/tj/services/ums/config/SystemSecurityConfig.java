package com.tj.services.ums.config;

import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.security.UserDetailsServiceImpl;
import com.tj.services.ums.utils.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import com.tj.services.ums.security.JwtAuthFilter;
import com.tj.services.ums.security.JwtBlacklistFilter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@ConfigurationProperties(prefix = "security.ip")
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
@Slf4j
public class SystemSecurityConfig {
    // Basic IP Controls
    private boolean allowUnlistedIps = false;
    private List<String> globalBlockedIps = new ArrayList<>();
    private List<String> allowedIpRanges = new ArrayList<>();

    // GeoIP Controls
    private boolean enableGeoIpFiltering = false;
    private boolean blockUnknownCountries = true;
    private List<String> blockedCountries = new ArrayList<>();

    // Rate Limiting
    private int maxAttemptsPerMinute = 10;

    // Internal parsed data
    private final Set<String> normalizedBlockedIps = new HashSet<>();
    private final List<CIDRRange> cidrRanges = new ArrayList<>();
    private final Set<String> normalizedBlockedCountries = new HashSet<>();

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Autowired
    private JwtBlacklistFilter jwtBlacklistFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @PostConstruct
    public void init() {
        log.info("SystemSecurityConfig: allowUnlistedIps = {}", allowUnlistedIps);
        // Normalize all IPs and validate them
        this.normalizedBlockedIps.addAll(
                globalBlockedIps.stream()
                        .map(this::normalizeIp)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet())
        );

        // Parse CIDR ranges
        this.cidrRanges.addAll(
                allowedIpRanges.stream()
                        .map(CIDRRange::parse)
                        .filter(Objects::nonNull)
                        .toList()
        );

        // Normalize country codes
        this.normalizedBlockedCountries.addAll(
                blockedCountries.stream()
                        .map(String::toUpperCase)
                        .filter(code -> code.matches("[A-Z]{2}"))
                        .collect(Collectors.toSet())
        );
    }

    // IP Validation Methods
    public boolean isIpAllowed(String ipAddress) {
        if (!StringUtils.hasText(ipAddress)) {
            return false;
        }

        String normalizedIp = normalizeIp(ipAddress);
        if (normalizedIp == null) {
            return false;
        }

        // 1. Check against global blocklist
        if (normalizedBlockedIps.contains(normalizedIp)) {
            return false;
        }

        // 2. Check if IP matches any allowed CIDR ranges
        if (!cidrRanges.isEmpty()) {
            boolean inRange = cidrRanges.stream()
                    .anyMatch(range -> range.contains(normalizedIp));
            if (inRange) return true;
        }

        // 3. Default to allowUnlistedIps setting
        return allowUnlistedIps;
    }

    // GeoIP Methods
    public boolean isCountryBlocked(String countryCode) {
        if (!enableGeoIpFiltering || !StringUtils.hasText(countryCode)) {
            return false;
        }
        return normalizedBlockedCountries.contains(countryCode.toUpperCase());
    }

    // IP Normalization
    private String normalizeIp(String ip) {
        try {
            return InetAddress.getByName(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    // Getters and Setters
    public boolean isAllowUnlistedIps() {
        return allowUnlistedIps;
    }

    public void setAllowUnlistedIps(boolean allowUnlistedIps) {
        this.allowUnlistedIps = allowUnlistedIps;
    }

    public List<String> getGlobalBlockedIps() {
        return Collections.unmodifiableList(globalBlockedIps);
    }

    public void setGlobalBlockedIps(List<String> globalBlockedIps) {
        this.globalBlockedIps = globalBlockedIps != null ? globalBlockedIps : new ArrayList<>();
    }

    public List<String> getAllowedIpRanges() {
        return Collections.unmodifiableList(allowedIpRanges);
    }

    public void setAllowedIpRanges(List<String> allowedIpRanges) {
        this.allowedIpRanges = allowedIpRanges != null ? allowedIpRanges : new ArrayList<>();
    }

    public boolean isEnableGeoIpFiltering() {
        return enableGeoIpFiltering;
    }

    public void setEnableGeoIpFiltering(boolean enableGeoIpFiltering) {
        this.enableGeoIpFiltering = enableGeoIpFiltering;
    }

    public boolean isBlockUnknownCountries() {
        return blockUnknownCountries;
    }

    public void setBlockUnknownCountries(boolean blockUnknownCountries) {
        this.blockUnknownCountries = blockUnknownCountries;
    }

    public List<String> getBlockedCountries() {
        return Collections.unmodifiableList(blockedCountries);
    }

    public void setBlockedCountries(List<String> blockedCountries) {
        this.blockedCountries = blockedCountries != null ? blockedCountries : new ArrayList<>();
    }

    public int getMaxAttemptsPerMinute() {
        return maxAttemptsPerMinute;
    }

    public void setMaxAttemptsPerMinute(int maxAttemptsPerMinute) {
        this.maxAttemptsPerMinute = maxAttemptsPerMinute;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter, JwtBlacklistFilter jwtBlacklistFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtBlacklistFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/login",
                                "/api/v1/auth/register",
                                "/api/v1/auth/otp/login",
                                "/api/v1/auth/otp/email/request",
                                "/api/v1/auth/otp/email/login",
                                "/api/v1/auth/refresh",
                                "/ums/v1/build-status",
                                "/actuator/health"
                        ).permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    // CIDR Range Helper Class
    public static class CIDRRange {
        private final byte[] network;
        private final byte[] netmask;
        private final int prefixLength;

        private CIDRRange(byte[] network, byte[] netmask, int prefixLength) {
            this.network = network;
            this.netmask = netmask;
            this.prefixLength = prefixLength;
        }

        public static CIDRRange parse(String cidr) {
            try {
                String[] parts = cidr.split("/");
                byte[] network = InetAddress.getByName(parts[0]).getAddress();
                int prefixLength = Integer.parseInt(parts[1]);

                byte[] netmask = new byte[network.length];
                for (int i = 0; i < netmask.length; i++) {
                    int shift = 8 - Math.min(8, Math.max(0, prefixLength - i * 8));
                    netmask[i] = (byte) (0xff << shift);
                }

                return new CIDRRange(network, netmask, prefixLength);
            } catch (Exception e) {
                return null;
            }
        }

        public boolean contains(String ipAddress) {
            try {
                byte[] address = InetAddress.getByName(ipAddress).getAddress();
                if (address.length != network.length) return false;

                for (int i = 0; i < address.length; i++) {
                    if ((address[i] & netmask[i]) != (network[i] & netmask[i])) {
                        return false;
                    }
                }
                return true;
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }
}
package com.tj.services.ums.config;

import com.tj.services.ums.security.JwtAuthFilter;
import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.utils.JwtUtil;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@TestConfiguration
@EnableWebSecurity
public class KycControllerTestConfig {

    @Bean
    public JwtUtil jwtUtil() {
        JwtUtil jwtUtil = Mockito.mock(JwtUtil.class);
        // Mock JWT token validation to always return true for tests
        Mockito.when(jwtUtil.isTokenValid(Mockito.anyString(), Mockito.any())).thenReturn(true);
        Mockito.when(jwtUtil.extractUsername(Mockito.anyString())).thenReturn("testuser");
        return jwtUtil;
    }

    @Bean
    public JwtAuthFilter jwtAuthFilter(JwtUtil jwtUtil) {
        // Create a mock JwtAuthFilter with the mocked JwtUtil
        JwtAuthFilter filter = Mockito.mock(JwtAuthFilter.class);
        return filter;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // Provide a minimal UserDetailsService for testing
        UserDetails user = User.withUsername("testuser")
            .password("password")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public TokenBlacklistService tokenBlacklistService() {
        return Mockito.mock(TokenBlacklistService.class);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            );
        return http.build();
    }
}

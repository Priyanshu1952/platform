package com.tj.services.ums.config;

import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.service.impl.InMemoryTokenBlacklistServiceImpl;
import com.tj.services.ums.utils.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Profile("test")
public class TestConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public TokenBlacklistService tokenBlacklistService(JwtUtil jwtUtil) {
        return new InMemoryTokenBlacklistServiceImpl(jwtUtil);
    }
}

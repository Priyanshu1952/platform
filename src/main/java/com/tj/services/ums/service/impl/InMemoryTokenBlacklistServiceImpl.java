package com.tj.services.ums.service.impl;

import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Profile("dev") // Only active in 'dev' profile
@Slf4j
public class InMemoryTokenBlacklistServiceImpl implements TokenBlacklistService {
    private static final Map<String, Long> blacklist = new ConcurrentHashMap<>();
    private final JwtUtil jwtUtil;

    public InMemoryTokenBlacklistServiceImpl(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void blacklistToken(String token) {
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            Date expiration = jwtUtil.extractExpiration(token);
            if (jti == null || expiration == null) {
                log.warn("Cannot blacklist token: jti or expiration is null");
                return;
            }
            blacklist.put(jti, expiration.getTime());
            log.debug("Token blacklisted successfully: {}", jti);
        } catch (JwtException e) {
            log.error("Invalid JWT token during blacklist: {}", e.getMessage());
            throw new IllegalStateException("Invalid JWT token", e);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        if (token == null) {
            log.debug("isTokenBlacklisted called with null token");
            return false;
        }
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            Long expiry = blacklist.get(jti);
            if (expiry == null) return false;
            if (expiry < System.currentTimeMillis()) {
                blacklist.remove(jti);
                log.debug("Expired token removed from blacklist: {}", jti);
                return false;
            }
            return true;
        } catch (JwtException e) {
            log.warn("Invalid JWT token during blacklist check: {}", e.getMessage());
            return true; // Treat invalid tokens as blacklisted
        }
    }
}

package com.tj.services.ums.service.impl;

import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Profile("dev") // Only active in 'dev' profile
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
                System.out.println("[InMemoryTokenBlacklistServiceImpl] Cannot blacklist token: jti or expiration is null. Token: " + token);
                return;
            }
            blacklist.put(jti, expiration.getTime());
        } catch (JwtException e) {
            System.out.println("[InMemoryTokenBlacklistServiceImpl] Invalid JWT token during blacklist: " + e.getMessage());
            throw new IllegalStateException("Invalid JWT token", e);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        if (token == null) {
            System.out.println("[InMemoryTokenBlacklistServiceImpl] isTokenBlacklisted called with null token");
            return false;
        }
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            Long expiry = blacklist.get(jti);
            if (expiry == null) return false;
            if (expiry < System.currentTimeMillis()) {
                blacklist.remove(jti);
                return false;
            }
            return true;
        } catch (JwtException e) {
            return true; // Treat invalid tokens as blacklisted
        }
    }
}

package com.tj.services.ums.service.impl;

import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistServiceImpl implements TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "bl_";
    private final JwtUtil jwtUtil;

    @Override
    public void blacklistToken(String token) {
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            Date expiration = jwtUtil.extractExpiration(token);
            long ttl = expiration.getTime() - System.currentTimeMillis();

        } catch (JwtException e) {
            throw new IllegalStateException("Invalid JWT token", e);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            return false;
        } catch (JwtException e) {
            return true; // Treat invalid tokens as blacklisted
        }
    }
}


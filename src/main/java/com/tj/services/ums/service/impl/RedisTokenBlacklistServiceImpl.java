package com.tj.services.ums.service.impl;


// COMMENTED OUT FOR DEVELOPMENT MODE
// This implementation is disabled to prevent Redis connections in dev profile.
// The in-memory implementation (InMemoryTokenBlacklistServiceImpl) should be used for dev.
/*
@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistServiceImpl implements TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "bl_";
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtil jwtUtil;

    @Override
    public void blacklistToken(String token) {
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            Date expiration = jwtUtil.extractExpiration(token);
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                redisTemplate.opsForValue().set(BLACKLIST_PREFIX + jti, "", ttl, TimeUnit.MILLISECONDS);
            }
        } catch (JwtException e) {
            throw new IllegalStateException("Invalid JWT token", e);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        try {
            String jti = jwtUtil.extractClaim(token, Claims::getId);
            return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti));
        } catch (JwtException e) {
            return true; // Treat invalid tokens as blacklisted
        }
    }
}
*/


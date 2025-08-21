package com.tj.services.ums.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.codec.Hex;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    private long accessTokenExpiration;

    private final long refreshTokenExpiration;

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    public JwtUtil(@Value("${jwt.secret}") String secretKey, @Value("${jwt.access-token-expiry:360000}") long accessTokenExpiration, @Value("${jwt.refresh-token-expiry:864000}") long refreshTokenExpiration) {
        this.secretKey = secretKey;
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, accessTokenExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "REFRESH");
        return generateToken(claims, userDetails, refreshTokenExpiration);
    }

    private String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Hex.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generate JWT token for emulated user session
     * @param targetUser The user being emulated
     * @param emulatingUserId The ID of the user doing the emulation
     * @return JWT token with emulation claims
     */
    public String generateEmulatedAccessToken(com.tj.services.ums.model.User targetUser, java.util.UUID emulatingUserId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("emulated", true);
        claims.put("emulated_by", emulatingUserId.toString());
        claims.put("target_user_id", targetUser.getId().toString());
        claims.put("target_user_email", targetUser.getEmail());
        
        // Create UserDetails for the target user
        UserDetails targetUserDetails = createUserDetailsFromUser(targetUser);
        
        return generateToken(claims, targetUserDetails, accessTokenExpiration);
    }
    
    /**
     * Extract emulation claims from JWT token
     * @param token JWT token
     * @return Map containing emulation information
     */
    public Map<String, Object> extractEmulationClaims(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Map<String, Object> emulationInfo = new HashMap<>();
            
            emulationInfo.put("emulated", claims.get("emulated", Boolean.class));
            emulationInfo.put("emulated_by", claims.get("emulated_by", String.class));
            emulationInfo.put("target_user_id", claims.get("target_user_id", String.class));
            emulationInfo.put("target_user_email", claims.get("target_user_email", String.class));
            
            return emulationInfo;
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
    
    /**
     * Check if a token represents an emulated session
     * @param token JWT token
     * @return true if token represents emulated session
     */
    public boolean isEmulatedToken(String token) {
        try {
            Boolean emulated = extractClaim(token, claims -> claims.get("emulated", Boolean.class));
            return Boolean.TRUE.equals(emulated);
        } catch (Exception e) {
            return false;
        }
    }
    
    private UserDetails createUserDetailsFromUser(com.tj.services.ums.model.User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                "", // No password needed for emulation
                java.util.Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }

    public boolean validateRefreshToken(String token) {
        try {
            return !isTokenExpired(token) &&
                    extractClaim(token, Claims::getSubject) != null &&
                    "REFRESH".equals(extractClaim(token, c -> c.get("type", String.class)));
        } catch (JwtException e) {
            return false;
        }
    }

    public String extractToken(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    public Date getAccessTokenExpiry() {
        return new Date(System.currentTimeMillis() + accessTokenExpiration);
    }

    public long getAccessTokenExpiryInMillis() {
        return System.currentTimeMillis() + accessTokenExpiration;
    }

    public Instant getAccessTokenExpiryInstant() {
        return Instant.now().plusMillis(accessTokenExpiration);
    }

    @PostConstruct
    public void init() {
        log.info("JWT secret: {}", secretKey);
    }

}
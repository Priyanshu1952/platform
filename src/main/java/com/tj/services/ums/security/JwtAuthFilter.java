package com.tj.services.ums.security;

import com.tj.services.ums.model.EmulationContext;
import com.tj.services.ums.model.EmulationSession;
import com.tj.services.ums.model.EmulationStatus;
import com.tj.services.ums.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        log.debug("Processing JWT authentication for request: {}", request.getRequestURI());
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("Missing or invalid Authorization header");
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtUtil.extractUsername(jwt);
        log.debug("Extracted user email: {}", userEmail);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            boolean valid = jwtUtil.isTokenValid(jwt, userDetails);
            log.debug("Token validation result: {}", valid);
            if (valid) {
                // Check if this is an emulated session
                Boolean isEmulated = jwtUtil.extractClaim(jwt, claims -> claims.get("emulated", Boolean.class));
                String emulatedBy = jwtUtil.extractClaim(jwt, claims -> claims.get("emulated_by", String.class));
                
                if (Boolean.TRUE.equals(isEmulated) && emulatedBy != null) {
                    // This is an emulated session
                    log.info("Processing emulated session for user {} emulated by {}", userEmail, emulatedBy);
                    
                    // Set emulation context
                    EmulationContext.setCurrentSession(createEmulationSessionFromToken(jwt, userDetails, emulatedBy));
                }
                
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.debug("Authentication set for user: {}", userEmail);
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.equals("/api/v1/auth/login") ||
                requestURI.equals("/api/v1/auth/register") ||
                requestURI.equals("/api/v1/auth/otp/login");
    }
    
    private EmulationSession createEmulationSessionFromToken(String jwt, UserDetails userDetails, String emulatedBy) {
        // Extract emulation details from JWT claims
        String targetUserId = jwtUtil.extractClaim(jwt, claims -> claims.get("target_user_id", String.class));
        String targetUserEmail = jwtUtil.extractClaim(jwt, claims -> claims.get("target_user_email", String.class));
        
        return EmulationSession.builder()
                .emulatingUserId(UUID.fromString(emulatedBy))
                .targetUserId(UUID.fromString(targetUserId))
                .sessionToken(jwt)
                .startTime(LocalDateTime.now())
                .status(EmulationStatus.ACTIVE)
                .build();
    }
}
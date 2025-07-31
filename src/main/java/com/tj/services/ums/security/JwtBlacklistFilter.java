package com.tj.services.ums.security;

import com.tj.services.ums.service.TokenBlacklistService;
import com.tj.services.ums.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtBlacklistFilter extends OncePerRequestFilter {

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {


        System.out.println("doInternal called in JwtBlacklistFilter");
String token = jwtUtil.extractToken(request);
System.out.println("[JwtBlacklistFilter] Extracted token: " + token);
boolean isBlacklisted = false;
try {
    if (token != null) {
        isBlacklisted = tokenBlacklistService.isTokenBlacklisted(token);
        System.out.println("[JwtBlacklistFilter] isTokenBlacklisted: " + isBlacklisted);
    }
} catch (Exception e) {
    System.out.println("[JwtBlacklistFilter] Exception during blacklist check: " + e.getMessage());
}
if (token != null && isBlacklisted) {
            response.setContentType("application/json");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(
                    "{\"error\":\"invalid_token\",\"message\":\"Token has been invalidated\"}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}
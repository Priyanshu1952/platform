package com.tj.services.ums.security;

import com.tj.services.ums.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.Comment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
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
System.out.println("[JwtAuthFilter] Authorization header: " + authHeader);
final String jwt;
final String userEmail;

if (authHeader == null || !authHeader.startsWith("Bearer ")) {
    System.out.println("[JwtAuthFilter] Missing or invalid Authorization header");
    filterChain.doFilter(request, response);
    return;
}

jwt = authHeader.substring(7);
System.out.println("[JwtAuthFilter] Extracted JWT: " + jwt);
userEmail = jwtUtil.extractUsername(jwt);
System.out.println("[JwtAuthFilter] Extracted userEmail: " + userEmail);

if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
    boolean valid = jwtUtil.isTokenValid(jwt, userDetails);
    System.out.println("[JwtAuthFilter] isTokenValid: " + valid);
    if (valid) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    } else {
        System.out.println("[JwtAuthFilter] Token is NOT valid");
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
}
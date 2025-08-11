package com.tj.services.ums.security.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tj.services.ums.dto.ApiResponse;
import com.tj.services.ums.security.annotation.CustomRequestProcessor;
import com.tj.services.ums.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityInterceptor implements HandlerInterceptor {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true; // Not a controller method
        }

        // Check annotation on method first, then on class
        Method method = handlerMethod.getMethod();
        CustomRequestProcessor ann = method.getAnnotation(CustomRequestProcessor.class);
        if (ann == null) {
            ann = handlerMethod.getBeanType().getAnnotation(CustomRequestProcessor.class);
        }
        if (ann == null) {
            return true; // No annotation → no extra checks
        }

        Set<String> requiredRoles = Arrays.stream(ann.areaRole())
                .filter(s -> s != null && !s.isBlank())
                .map(String::trim)
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .collect(Collectors.toSet());

        // Retrieve authentication from SecurityContext (JwtAuthFilter should have set it)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return writeError(response, 401, "801", "Authorization unsuccessful.Either email/mobile or password is invalid");
        }

        // Extract granted authorities
        Set<String> granted = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Authorize: All required roles must be present (AND semantics). Change to OR if desired.
        Set<String> missing = new HashSet<>(requiredRoles);
        missing.removeAll(granted);
        if (!missing.isEmpty()) {
            log.warn("Access denied. Required roles: {}, Granted: {}", requiredRoles, granted);
            return writeError(response, 403, "801", "Authorization unsuccessful.Either email/mobile or password is invalid");
        }

        return true;
    }

    private boolean writeError(HttpServletResponse response, int httpStatus, String errCode, String message) throws IOException {
        ApiResponse.Status status = ApiResponse.Status.builder()
                .success(false)
                .httpStatus(httpStatus)
                .build();
        ApiResponse.ApiError error = ApiResponse.ApiError.builder()
                .errCode(errCode)
                .message(message)
                .build();
        ApiResponse body = ApiResponse.builder()
                .status(status)
                .errors(Arrays.asList(error))
                .build();

        response.setStatus(httpStatus);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
        return false;
    }
} 
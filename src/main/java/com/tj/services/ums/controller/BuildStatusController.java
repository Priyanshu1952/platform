package com.tj.services.ums.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for build status and application information
 */
@Slf4j
@RestController
@RequestMapping("/ums/v1")
@RequiredArgsConstructor
@Tag(name = "Build Status", description = "Endpoints for build and application status")
public class BuildStatusController {

    @Value("${spring.application.name:ums}")
    private String applicationName;

    @Value("${server.port:8085}")
    private String serverPort;

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    /**
     * Returns the build status of the service
     */
    @GetMapping("/build-status")
    @Operation(summary = "Get build status", description = "Returns the build status and application information")
    public ResponseEntity<Map<String, Object>> getBuildStatus() {
        log.info("Build status requested");
        
        Map<String, Object> buildStatus = new HashMap<>();
        buildStatus.put("applicationName", applicationName);
        buildStatus.put("status", "UP");
        buildStatus.put("timestamp", LocalDateTime.now());
        buildStatus.put("serverPort", serverPort);
        buildStatus.put("activeProfile", activeProfile);
        buildStatus.put("version", "1.0.0");
        buildStatus.put("environment", activeProfile.toUpperCase());
        buildStatus.put("uptime", System.currentTimeMillis());
        
        return ResponseEntity.ok(buildStatus);
    }
} 
package com.tj.services.ums.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(basePackages = "com.tj.services.ums.repository")
public class JpaConfig {
    // JPA-specific configuration if needed
}
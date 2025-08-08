package com.tj.services.ums.initialization;

import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.Role;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        try {
            // Initialize roles
            initializeRoles();
            
            // Initialize admin user
            initializeAdminUser();
            
            log.info("Data initialization completed successfully");
        } catch (Exception e) {
            log.warn("Data initialization failed, this is normal during development: {}", e.getMessage());
            // Don't throw the exception to allow the application to continue
        }
    }

    private void initializeRoles() {
        // Check if roles already exist
        if (roleRepository.count() > 0) {
            log.info("Roles already exist, skipping role initialization");
            return;
        }

        // Create roles
        Role userRole = new Role();
        userRole.setName("ROLE_USER");
        roleRepository.save(userRole);

        Role agentRole = new Role();
        agentRole.setName("ROLE_AGENT");
        roleRepository.save(agentRole);

        Role adminRole = new Role();
        adminRole.setName("ROLE_ADMIN");
        roleRepository.save(adminRole);

        log.info("Roles initialized successfully");
    }

    private void initializeAdminUser() {
        // Check if admin user already exists
        if (authUserRepository.findByEmail("admin@ums.com").isPresent()) {
            log.info("Admin user already exists, skipping admin user initialization");
            return;
        }

        // Create admin user
        AuthUser adminUser = new AuthUser();
        adminUser.setEmail("admin@ums.com");
        adminUser.setName("System Administrator");
        adminUser.setMobile("9999999999");
        adminUser.setPassword(passwordEncoder.encode("admin123"));
        adminUser.setEmailVerified(true);
        adminUser.setActive(true);
        
        // Set roles - find each role individually
        java.util.Set<Role> adminRoles = new java.util.HashSet<>();
        roleRepository.findByName("ROLE_ADMIN").ifPresent(adminRoles::add);
        roleRepository.findByName("ROLE_USER").ifPresent(adminRoles::add);
        adminUser.setRoles(adminRoles);

        authUserRepository.save(adminUser);
        log.info("Admin user initialized successfully");
    }
}
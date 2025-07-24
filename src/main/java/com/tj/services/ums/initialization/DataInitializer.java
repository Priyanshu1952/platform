package com.tj.services.ums.initialization;

import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.Role;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            roleRepository.save(userRole);
        }

        if (authUserRepository.findByEmail("test@example.com").isEmpty()) {
            Role userRole = roleRepository.findByName("ROLE_USER").get();
            AuthUser user = AuthUser.builder()
                    .name("Test User")
                    .email("test@example.com")
                    .mobile("1234567890")
                    .password(passwordEncoder.encode("Password123!"))
                    .emailVerified(true)
                    .roles(Set.of(userRole))
                    .build();
            authUserRepository.save(user);
        }
    }
}
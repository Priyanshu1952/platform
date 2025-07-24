package com.tj.services.ums.repository;

import com.tj.services.ums.model.AuthUser;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;


@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {
    boolean existsByEmail(String email);
    Optional<AuthUser> findByEmail(String email);

    Optional<AuthUser> findByMobile(@NotBlank(message = "Mobile number must not be blank") @Pattern(regexp = "\\d{10}", message = "Mobile number must be 10 digits") String mobile);

    Optional<AuthUser> findByVerificationToken(String token);

//    @Override
//    Optional<AuthUser> save(AuthUser user);
}

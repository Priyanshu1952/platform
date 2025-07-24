package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.UserProfileUpdateRequest;
import com.tj.services.ums.exception.AuthException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.service.UserProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class UserProfileServiceImpl implements UserProfileService {

    private final AuthUserRepository authUserRepository;

    @Override
    public AuthUser getUserProfile(UUID userId) {
        return authUserRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found with ID: " + userId));
    }

    @Override
    public AuthUser updateUserProfile(UUID userId, UserProfileUpdateRequest request) {
        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found with ID: " + userId));

        user.setName(request.name());
        user.setMobile(request.mobile());

        return authUserRepository.save(user);
    }
}

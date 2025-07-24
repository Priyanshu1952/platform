package com.tj.services.ums.service;

import com.tj.services.ums.dto.UserProfileUpdateRequest;
import com.tj.services.ums.model.AuthUser;

import java.util.UUID;

public interface UserProfileService {
    AuthUser getUserProfile(UUID userId);
    AuthUser updateUserProfile(UUID userId, UserProfileUpdateRequest request);
}
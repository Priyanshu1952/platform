package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.UserUpdateRequest;
import com.tj.services.ums.exception.AuthException;
import com.tj.services.ums.model.AuthUser;
import com.tj.services.ums.model.User;
import com.tj.services.ums.model.UserAdditionalInfo;
import com.tj.services.ums.model.UserConfiguration;
import com.tj.services.ums.repository.AuthUserRepository;
import com.tj.services.ums.repository.UserRepository;
import com.tj.services.ums.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserServiceImpl implements UserService {

    private final AuthUserRepository authUserRepository;
    private final UserRepository userRepository;

    // AuthUser operations
    @Override
    public AuthUser getAuthUserById(UUID userId) {
        return authUserRepository.findById(userId)
                .orElseThrow(() -> new AuthException("AuthUser not found with ID: " + userId));
    }

    @Override
    public AuthUser updateAuthUser(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        
        // Update basic information
        if (StringUtils.hasText(request.name())) {
            authUser.setName(request.name());
        }
        
        if (StringUtils.hasText(request.email())) {
            // Check if email is available
            if (!isEmailAvailable(request.email(), userId)) {
                throw new AuthException("Email already exists: " + request.email());
            }
            authUser.setEmail(request.email());
        }
        
        if (StringUtils.hasText(request.mobile())) {
            // Check if mobile is available
            if (!isMobileAvailable(request.mobile(), userId)) {
                throw new AuthException("Mobile number already exists: " + request.mobile());
            }
            authUser.setMobile(request.mobile());
        }
        
        // Update verification status
        if (request.emailVerified() != null) {
            authUser.setEmailVerified(request.emailVerified());
        }
        
        if (request.panVerified() != null) {
            authUser.setPanVerified(request.panVerified());
        }
        
        if (request.aadhaarVerified() != null) {
            authUser.setAadhaarVerified(request.aadhaarVerified());
        }
        
        return authUserRepository.save(authUser);
    }

    @Override
    public AuthUser updateAuthUserSecurity(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        
        // Update security configuration
        if (request.require2fa() != null) {
            authUser.setRequire2fa(request.require2fa());
        }
        
        if (request.deviceLimit() != null) {
            authUser.setDeviceLimit(request.deviceLimit());
        }
        
        if (request.accountLocked() != null) {
            authUser.setAccountLocked(request.accountLocked());
        }
        
        if (request.allowedIps() != null) {
            String allowedIpsString = String.join(",", request.allowedIps());
            authUser.setAllowedIps(allowedIpsString);
        }
        
        return authUserRepository.save(authUser);
    }

    @Override
    public Optional<AuthUser> getAuthUserByEmail(String email) {
        return authUserRepository.findByEmail(email);
    }

    // User operations (business logic)
    @Override
    public User getUserById(Long userId) {
        // Convert Long to UUID for repository lookup
        // Note: This is a temporary fix. The interface should be updated to use UUID
        throw new UnsupportedOperationException("getUserById with Long is not supported. Use getUserByUserId instead.");
    }

    @Override
    public User getUserByUserId(String userId) {
        return userRepository.findByUserId(userId)
                .orElseThrow(() -> new AuthException("User not found with userId: " + userId));
    }

    @Override
    public User updateUser(Long userId, UserUpdateRequest request) {
        User user = getUserById(userId);
        return updateUserFields(user, request);
    }

    @Override
    public User updateUserByUserId(String userId, UserUpdateRequest request) {
        User user = getUserByUserId(userId);
        return updateUserFields(user, request);
    }

    private User updateUserFields(User user, UserUpdateRequest request) {
        // Update basic information
        if (StringUtils.hasText(request.name())) {
            user.setName(request.name());
        }
        
        if (StringUtils.hasText(request.email())) {
            user.setEmail(request.email());
        }
        
        if (StringUtils.hasText(request.mobile())) {
            user.setMobile(request.mobile());
        }
        
        if (StringUtils.hasText(request.phone())) {
            user.setPhone(request.phone());
        }
        
        // Update role and status
        if (request.role() != null) {
            user.setRole(request.role());
        }
        
        if (request.status() != null) {
            user.setStatus(request.status());
        }
        
        // Update business information
        if (StringUtils.hasText(request.partnerId())) {
            user.setPartnerId(request.partnerId());
        }
        
        if (StringUtils.hasText(request.employeeId())) {
            user.setEmployeeId(request.employeeId());
        }
        
        if (StringUtils.hasText(request.salesUserId())) {
            user.setSalesUserId(request.salesUserId());
        }
        
        // Update financial information
        if (request.balance() != null) {
            user.setBalance(request.balance());
        }
        
        if (request.walletBalance() != null) {
            user.setWalletBalance(request.walletBalance());
        }
        
        if (request.totalBalance() != null) {
            user.setTotalBalance(request.totalBalance());
        }
        
        if (StringUtils.hasText(request.walletOrCreditStatus())) {
            user.setWalletOrCreditStatus(request.walletOrCreditStatus());
        }
        
        // Update profile information
        if (request.userProfile() != null) {
            user.setUserProfile(request.userProfile());
        }
        
        // Update address information
        if (request.addressInfo() != null) {
            user.setAddressInfo(request.addressInfo());
        }
        
        // Update contact person information
        if (request.contactPersonInfo() != null) {
            user.setContactPersonInfo(request.contactPersonInfo());
        }
        
        // Update KYC information
        if (request.gstInfo() != null) {
            user.setGstInfo(request.gstInfo());
        }
        
        if (request.panInfo() != null) {
            user.setPanInfo(request.panInfo());
        }
        
        // Update additional information
        if (request.additionalInfo() != null) {
            UserAdditionalInfo additionalInfo = new UserAdditionalInfo();
            additionalInfo.setCustomFields(request.additionalInfo());
            user.setAdditionalInfo(additionalInfo);
        }
        
        if (request.railAdditionalInfo() != null) {
            // Convert Map to RailAdditionalInfo if needed
            // For now, we'll store it as additional info
            UserAdditionalInfo railInfo = new UserAdditionalInfo();
            railInfo.setCustomFields(request.railAdditionalInfo());
            // You might want to create a proper RailAdditionalInfo model
        }
        
        if (request.railOnboardingStartDate() != null) {
            user.setRailOnboardingStartDate(request.railOnboardingStartDate());
        }
        
        // Update parent/emulation information
        if (StringUtils.hasText(request.parentUserId())) {
            user.setParentUserId(request.parentUserId());
        }
        
        if (request.canBeEmulated() != null) {
            user.setCanBeEmulated(request.canBeEmulated());
        }
        
        // Update configuration
        if (request.userConf() != null) {
            UserConfiguration userConf = new UserConfiguration();
            userConf.setSettings(request.userConf());
            user.setUserConf(userConf);
        }
        
        // Update flags
        if (request.showUnmaskedDetails() != null) {
            user.setShowUnmaskedDetails(request.showUnmaskedDetails());
        }
        
        return userRepository.save(user);
    }

    // Combined operations
    @Override
    public UserUpdateRequest getUserUpdateRequest(UUID authUserId) {
        AuthUser authUser = getAuthUserById(authUserId);
        Optional<User> userOpt = userRepository.findByEmail(authUser.getEmail());
        
        UserUpdateRequest.Builder builder = UserUpdateRequest.builder()
                .name(authUser.getName())
                .email(authUser.getEmail())
                .mobile(authUser.getMobile())
                .emailVerified(authUser.getEmailVerified())
                .panVerified(authUser.getPanVerified())
                .aadhaarVerified(authUser.getAadhaarVerified())
                .require2fa(authUser.getRequire2fa())
                .deviceLimit(authUser.getDeviceLimit())
                .accountLocked(authUser.getAccountLocked());
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            builder.role(user.getRole())
                    .status(user.getStatus())
                    .partnerId(user.getPartnerId())
                    .employeeId(user.getEmployeeId())
                    .balance(user.getBalance())
                    .walletBalance(user.getWalletBalance())
                    .totalBalance(user.getTotalBalance())
                    .userProfile(user.getUserProfile())
                    .addressInfo(user.getAddressInfo())
                    .contactPersonInfo(user.getContactPersonInfo())
                    .gstInfo(user.getGstInfo())
                    .panInfo(user.getPanInfo())
                    .canBeEmulated(user.getCanBeEmulated());
        }
        
        return builder.build();
    }

    @Override
    public UserUpdateRequest getUserUpdateRequestByUserId(String userId) {
        User user = getUserByUserId(userId);
        Optional<AuthUser> authUserOpt = authUserRepository.findByEmail(user.getEmail());
        
        UserUpdateRequest.Builder builder = UserUpdateRequest.builder()
                .name(user.getName())
                .email(user.getEmail())
                .mobile(user.getMobile())
                .phone(user.getPhone())
                .role(user.getRole())
                .status(user.getStatus())
                .partnerId(user.getPartnerId())
                .employeeId(user.getEmployeeId())
                .balance(user.getBalance())
                .walletBalance(user.getWalletBalance())
                .totalBalance(user.getTotalBalance())
                .userProfile(user.getUserProfile())
                .addressInfo(user.getAddressInfo())
                .contactPersonInfo(user.getContactPersonInfo())
                .gstInfo(user.getGstInfo())
                .panInfo(user.getPanInfo())
                .canBeEmulated(user.getCanBeEmulated());
        
        if (authUserOpt.isPresent()) {
            AuthUser authUser = authUserOpt.get();
            builder.emailVerified(authUser.getEmailVerified())
                    .panVerified(authUser.getPanVerified())
                    .aadhaarVerified(authUser.getAadhaarVerified())
                    .require2fa(authUser.getRequire2fa())
                    .deviceLimit(authUser.getDeviceLimit())
                    .accountLocked(authUser.getAccountLocked());
        }
        
        return builder.build();
    }

    // User relationship operations
    @Override
    public List<String> getAllowedUserIds(String userId) {
        // Implementation would depend on your business logic
        // For now, return empty list
        return List.of();
    }

    @Override
    public List<User> getUserRelations(String userId) {
        User user = getUserByUserId(userId);
        return user.getUserRelations() != null ? 
                user.getUserRelations().stream().collect(Collectors.toList()) : 
                List.of();
    }

    // Search and query operations
    @Override
    public Optional<User> getUserByUserId(String userId, boolean includeRelations) {
        Optional<User> userOpt = userRepository.findByUserId(userId);
        if (userOpt.isPresent() && includeRelations) {
            // Load relations if needed
            User user = userOpt.get();
            // Force load relations
            user.getUserRelations().size();
        }
        return userOpt;
    }

    @Override
    public List<User> searchUsers(String query) {
        // Implementation would depend on your search requirements
        // Using separate queries for name and email search
        List<User> nameResults = userRepository.findByNameContaining(query);
        List<User> emailResults = userRepository.findByEmailContaining(query);
        
        // Combine and remove duplicates
        Set<User> combinedResults = new HashSet<>();
        combinedResults.addAll(nameResults);
        combinedResults.addAll(emailResults);
        
        return new ArrayList<>(combinedResults);
    }

    @Override
    public List<User> getUsersByRole(String role) {
        return userRepository.findByRole(com.tj.services.ums.model.UserRole.valueOf(role));
    }

    @Override
    public List<User> getUsersByStatus(String status) {
        return userRepository.findByStatus(com.tj.services.ums.model.UserStatus.valueOf(status));
    }

    // Bulk operations
    @Override
    public List<User> updateMultipleUsers(List<Long> userIds, UserUpdateRequest request) {
        return userIds.stream()
                .map(userId -> updateUser(userId, request))
                .collect(Collectors.toList());
    }

    @Override
    public void deactivateUsers(List<Long> userIds) {
        userIds.forEach(userId -> {
            User user = getUserById(userId);
            user.setStatus(com.tj.services.ums.model.UserStatus.INACTIVE);
            userRepository.save(user);
        });
    }

    @Override
    public void activateUsers(List<Long> userIds) {
        userIds.forEach(userId -> {
            User user = getUserById(userId);
            user.setStatus(com.tj.services.ums.model.UserStatus.ACTIVE);
            userRepository.save(user);
        });
    }

    // Validation operations
    @Override
    public boolean isEmailAvailable(String email, UUID excludeUserId) {
        Optional<AuthUser> existingAuthUser = authUserRepository.findByEmail(email);
        if (existingAuthUser.isPresent() && !existingAuthUser.get().getId().equals(excludeUserId)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean isMobileAvailable(String mobile, UUID excludeUserId) {
        Optional<AuthUser> existingAuthUser = authUserRepository.findByMobile(mobile);
        if (existingAuthUser.isPresent() && !existingAuthUser.get().getId().equals(excludeUserId)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean isUserIdAvailable(String userId) {
        return userRepository.findByUserId(userId).isEmpty();
    }

    // Security operations
    @Override
    public void lockUserAccount(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setAccountLocked(true);
        authUser.setLockTime(System.currentTimeMillis());
        authUserRepository.save(authUser);
    }

    @Override
    public void unlockUserAccount(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setAccountLocked(false);
        authUser.setFailedAttempts(0);
        authUser.setLockTime(null);
        authUserRepository.save(authUser);
    }

    @Override
    public void resetFailedAttempts(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setFailedAttempts(0);
        authUserRepository.save(authUser);
    }

    @Override
    public void updateLastPasswordChange(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setLastPasswordChange(System.currentTimeMillis());
        authUserRepository.save(authUser);
    }

    // Profile operations
    @Override
    public void updateUserProfile(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        Optional<User> userOpt = userRepository.findByEmail(authUser.getEmail());
        
        if (StringUtils.hasText(request.name())) {
            authUser.setName(request.name());
        }
        
        if (request.userProfile() != null && userOpt.isPresent()) {
            User user = userOpt.get();
            user.setUserProfile(request.userProfile());
            userRepository.save(user);
        }
        
        authUserRepository.save(authUser);
    }

    @Override
    public void updateUserAddress(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        Optional<User> userOpt = userRepository.findByEmail(authUser.getEmail());
        
        if (request.addressInfo() != null && userOpt.isPresent()) {
            User user = userOpt.get();
            user.setAddressInfo(request.addressInfo());
            userRepository.save(user);
        }
    }

    @Override
    public void updateUserContactInfo(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        Optional<User> userOpt = userRepository.findByEmail(authUser.getEmail());
        
        if (StringUtils.hasText(request.mobile())) {
            authUser.setMobile(request.mobile());
        }
        
        if (request.contactPersonInfo() != null && userOpt.isPresent()) {
            User user = userOpt.get();
            user.setContactPersonInfo(request.contactPersonInfo());
            userRepository.save(user);
        }
        
        authUserRepository.save(authUser);
    }

    @Override
    public void updateUserKYCInfo(UUID userId, UserUpdateRequest request) {
        AuthUser authUser = getAuthUserById(userId);
        Optional<User> userOpt = userRepository.findByEmail(authUser.getEmail());
        
        if (request.panVerified() != null) {
            authUser.setPanVerified(request.panVerified());
        }
        
        if (request.aadhaarVerified() != null) {
            authUser.setAadhaarVerified(request.aadhaarVerified());
        }
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (request.gstInfo() != null) {
                user.setGstInfo(request.gstInfo());
            }
            if (request.panInfo() != null) {
                user.setPanInfo(request.panInfo());
            }
            userRepository.save(user);
        }
        
        authUserRepository.save(authUser);
    }

    // Verification operations
    @Override
    public void markEmailVerified(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setEmailVerified(true);
        authUserRepository.save(authUser);
    }

    @Override
    public void markPanVerified(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setPanVerified(true);
        authUserRepository.save(authUser);
    }

    @Override
    public void markAadhaarVerified(UUID userId) {
        AuthUser authUser = getAuthUserById(userId);
        authUser.setAadhaarVerified(true);
        authUserRepository.save(authUser);
    }

    // Financial operations
    @Override
    public void updateUserBalance(Long userId, Double newBalance) {
        User user = getUserById(userId);
        user.setBalance(newBalance);
        userRepository.save(user);
    }

    @Override
    public void updateUserWalletBalance(Long userId, Double newWalletBalance) {
        User user = getUserById(userId);
        user.setWalletBalance(newWalletBalance);
        userRepository.save(user);
    }

    @Override
    public void updateUserTotalBalance(Long userId, Double newTotalBalance) {
        User user = getUserById(userId);
        user.setTotalBalance(newTotalBalance);
        userRepository.save(user);
    }
} 
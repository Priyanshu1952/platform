package com.tj.services.ums.dto;

import com.tj.services.ums.model.AddressInfo;
import com.tj.services.ums.model.ContactPersonInfo;
import com.tj.services.ums.model.GSTInfo;
import com.tj.services.ums.model.PanInfo;
import com.tj.services.ums.model.UserProfile;
import com.tj.services.ums.model.UserRole;
import com.tj.services.ums.model.UserStatus;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Comprehensive DTO for updating user information
 * Supports updating both AuthUser and User model fields
 */
public record UserUpdateRequest(
        // Basic Information
        @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
        String name,
        
        @Email(message = "Invalid email format")
        String email,
        
        @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid mobile number format")
        String mobile,
        
        String phone,
        
        // Role and Status
        UserRole role,
        UserStatus status,
        
        // Business Information
        String partnerId,
        String employeeId,
        String salesUserId,
        
        // Financial Information
        Double balance,
        Double walletBalance,
        Double totalBalance,
        String walletOrCreditStatus,
        
        // Profile Information
        UserProfile userProfile,
        
        // Address Information
        AddressInfo addressInfo,
        
        // Contact Person Information
        ContactPersonInfo contactPersonInfo,
        
        // KYC Information
        GSTInfo gstInfo,
        PanInfo panInfo,
        
        // Verification Status
        Boolean emailVerified,
        Boolean panVerified,
        Boolean aadhaarVerified,
        
        // Security Configuration
        Boolean require2fa,
        Integer deviceLimit,
        Boolean accountLocked,
        List<String> allowedIps,
        
        // Additional Information
        Map<String, Object> additionalInfo,
        Map<String, Object> railAdditionalInfo,
        LocalDateTime railOnboardingStartDate,
        
        // Parent/Emulation Information
        String parentUserId,
        Boolean canBeEmulated,
        
        // Configuration
        Map<String, Object> userConf,
        
        // Flags
        Boolean showUnmaskedDetails
) {
    
    /**
     * Builder pattern for easier construction
     */
    public static class Builder {
        private String name;
        private String email;
        private String mobile;
        private String phone;
        private UserRole role;
        private UserStatus status;
        private String partnerId;
        private String employeeId;
        private String salesUserId;
        private Double balance;
        private Double walletBalance;
        private Double totalBalance;
        private String walletOrCreditStatus;
        private UserProfile userProfile;
        private AddressInfo addressInfo;
        private ContactPersonInfo contactPersonInfo;
        private GSTInfo gstInfo;
        private PanInfo panInfo;
        private Boolean emailVerified;
        private Boolean panVerified;
        private Boolean aadhaarVerified;
        private Boolean require2fa;
        private Integer deviceLimit;
        private Boolean accountLocked;
        private List<String> allowedIps;
        private Map<String, Object> additionalInfo;
        private Map<String, Object> railAdditionalInfo;
        private LocalDateTime railOnboardingStartDate;
        private String parentUserId;
        private Boolean canBeEmulated;
        private Map<String, Object> userConf;
        private Boolean showUnmaskedDetails;
        
        public Builder name(String name) {
            this.name = name;
            return this;
        }
        
        public Builder email(String email) {
            this.email = email;
            return this;
        }
        
        public Builder mobile(String mobile) {
            this.mobile = mobile;
            return this;
        }
        
        public Builder phone(String phone) {
            this.phone = phone;
            return this;
        }
        
        public Builder role(UserRole role) {
            this.role = role;
            return this;
        }
        
        public Builder status(UserStatus status) {
            this.status = status;
            return this;
        }
        
        public Builder partnerId(String partnerId) {
            this.partnerId = partnerId;
            return this;
        }
        
        public Builder employeeId(String employeeId) {
            this.employeeId = employeeId;
            return this;
        }
        
        public Builder salesUserId(String salesUserId) {
            this.salesUserId = salesUserId;
            return this;
        }
        
        public Builder balance(Double balance) {
            this.balance = balance;
            return this;
        }
        
        public Builder walletBalance(Double walletBalance) {
            this.walletBalance = walletBalance;
            return this;
        }
        
        public Builder totalBalance(Double totalBalance) {
            this.totalBalance = totalBalance;
            return this;
        }
        
        public Builder walletOrCreditStatus(String walletOrCreditStatus) {
            this.walletOrCreditStatus = walletOrCreditStatus;
            return this;
        }
        
        public Builder userProfile(UserProfile userProfile) {
            this.userProfile = userProfile;
            return this;
        }
        
        public Builder addressInfo(AddressInfo addressInfo) {
            this.addressInfo = addressInfo;
            return this;
        }
        
        public Builder contactPersonInfo(ContactPersonInfo contactPersonInfo) {
            this.contactPersonInfo = contactPersonInfo;
            return this;
        }
        
        public Builder gstInfo(GSTInfo gstInfo) {
            this.gstInfo = gstInfo;
            return this;
        }
        
        public Builder panInfo(PanInfo panInfo) {
            this.panInfo = panInfo;
            return this;
        }
        
        public Builder emailVerified(Boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }
        
        public Builder panVerified(Boolean panVerified) {
            this.panVerified = panVerified;
            return this;
        }
        
        public Builder aadhaarVerified(Boolean aadhaarVerified) {
            this.aadhaarVerified = aadhaarVerified;
            return this;
        }
        
        public Builder require2fa(Boolean require2fa) {
            this.require2fa = require2fa;
            return this;
        }
        
        public Builder deviceLimit(Integer deviceLimit) {
            this.deviceLimit = deviceLimit;
            return this;
        }
        
        public Builder accountLocked(Boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }
        
        public Builder allowedIps(List<String> allowedIps) {
            this.allowedIps = allowedIps;
            return this;
        }
        
        public Builder additionalInfo(Map<String, Object> additionalInfo) {
            this.additionalInfo = additionalInfo;
            return this;
        }
        
        public Builder railAdditionalInfo(Map<String, Object> railAdditionalInfo) {
            this.railAdditionalInfo = railAdditionalInfo;
            return this;
        }
        
        public Builder railOnboardingStartDate(LocalDateTime railOnboardingStartDate) {
            this.railOnboardingStartDate = railOnboardingStartDate;
            return this;
        }
        
        public Builder parentUserId(String parentUserId) {
            this.parentUserId = parentUserId;
            return this;
        }
        
        public Builder canBeEmulated(Boolean canBeEmulated) {
            this.canBeEmulated = canBeEmulated;
            return this;
        }
        
        public Builder userConf(Map<String, Object> userConf) {
            this.userConf = userConf;
            return this;
        }
        
        public Builder showUnmaskedDetails(Boolean showUnmaskedDetails) {
            this.showUnmaskedDetails = showUnmaskedDetails;
            return this;
        }
        
        public UserUpdateRequest build() {
            return new UserUpdateRequest(
                    name, email, mobile, phone, role, status, partnerId, employeeId, salesUserId,
                    balance, walletBalance, totalBalance, walletOrCreditStatus, userProfile,
                    addressInfo, contactPersonInfo, gstInfo, panInfo, emailVerified, panVerified,
                    aadhaarVerified, require2fa, deviceLimit, accountLocked, allowedIps,
                    additionalInfo, railAdditionalInfo, railOnboardingStartDate, parentUserId,
                    canBeEmulated, userConf, showUnmaskedDetails
            );
        }
    }
    
    public static Builder builder() {
        return new Builder();
    }
} 
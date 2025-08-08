package com.tj.services.ums.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotNull
    @Column(nullable = false)
    private String name;
    
    @NotNull
    @Column(nullable = false, unique = true)
    private String email;
    
    @NotNull
    @Column(nullable = false)
    private String mobile;
    
    private String phone;
    
    @Enumerated(EnumType.STRING)
    @NotNull
    @Column(nullable = false)
    private UserRole role;
    
    // Self-reference for emulation functionality
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "emulate_user_id")
    private User emulateUser;
    
    @Column(name = "user_id", unique = true)
    private String userId;
    
    @Column(name = "partner_id")
    private String partnerId;
    
    private Double balance;
    
    @Column(name = "wallet_balance")
    private Double walletBalance;
    
    @JsonProperty("wcstatus")
    @Column(name = "wallet_or_credit_status")
    private String walletOrCreditStatus;
    
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    @Column(name = "created_on")
    private LocalDateTime createdOn;
    
    @Column(name = "processed_on")
    private LocalDateTime processedOn;
    
    // Embedded info objects
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "gstNumber", column = @Column(name = "gst_number")),
        @AttributeOverride(name = "businessName", column = @Column(name = "gst_business_name")),
        @AttributeOverride(name = "businessType", column = @Column(name = "gst_business_type")),
        @AttributeOverride(name = "registrationDate", column = @Column(name = "gst_registration_date")),
        @AttributeOverride(name = "status", column = @Column(name = "gst_status")),
        @AttributeOverride(name = "state", column = @Column(name = "gst_state")),
        @AttributeOverride(name = "address", column = @Column(name = "gst_address")),
        @AttributeOverride(name = "verified", column = @Column(name = "gst_verified"))
    })
    private GSTInfo gstInfo;
    
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "panNumber", column = @Column(name = "pan_number")),
        @AttributeOverride(name = "fullName", column = @Column(name = "pan_full_name")),
        @AttributeOverride(name = "fatherName", column = @Column(name = "pan_father_name")),
        @AttributeOverride(name = "dateOfBirth", column = @Column(name = "pan_date_of_birth")),
        @AttributeOverride(name = "category", column = @Column(name = "pan_category")),
        @AttributeOverride(name = "panStatus", column = @Column(name = "pan_status")),
        @AttributeOverride(name = "aadhaarSeedingStatus", column = @Column(name = "pan_aadhaar_seeding_status")),
        @AttributeOverride(name = "lastUpdated", column = @Column(name = "pan_last_updated")),
        @AttributeOverride(name = "verified", column = @Column(name = "pan_verified"))
    })
    private PanInfo panInfo;
    
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "addressLine1", column = @Column(name = "address_line1")),
        @AttributeOverride(name = "addressLine2", column = @Column(name = "address_line2")),
        @AttributeOverride(name = "city", column = @Column(name = "address_city")),
        @AttributeOverride(name = "state", column = @Column(name = "address_state")),
        @AttributeOverride(name = "pincode", column = @Column(name = "address_pincode")),
        @AttributeOverride(name = "country", column = @Column(name = "address_country")),
        @AttributeOverride(name = "district", column = @Column(name = "address_district")),
        @AttributeOverride(name = "landmark", column = @Column(name = "address_landmark")),
        @AttributeOverride(name = "addressType", column = @Column(name = "address_type")),
        @AttributeOverride(name = "isPrimary", column = @Column(name = "address_is_primary")),
        @AttributeOverride(name = "verified", column = @Column(name = "address_verified"))
    })
    private AddressInfo addressInfo;
    
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "name", column = @Column(name = "contact_person_name")),
        @AttributeOverride(name = "designation", column = @Column(name = "contact_person_designation")),
        @AttributeOverride(name = "email", column = @Column(name = "contact_person_email")),
        @AttributeOverride(name = "mobile", column = @Column(name = "contact_person_mobile")),
        @AttributeOverride(name = "phone", column = @Column(name = "contact_person_phone")),
        @AttributeOverride(name = "department", column = @Column(name = "contact_person_department")),
        @AttributeOverride(name = "isPrimary", column = @Column(name = "contact_person_is_primary"))
    })
    private ContactPersonInfo contactPersonInfo;
    
    // JSON columns for complex objects (PostgreSQL JSONB support)
    @Column(name = "additional_info", columnDefinition = "json")
    @org.hibernate.annotations.JdbcTypeCode(java.sql.Types.OTHER)
    private UserAdditionalInfo additionalInfo;
    
    @Column(name = "rail_additional_info", columnDefinition = "json")
    @org.hibernate.annotations.JdbcTypeCode(java.sql.Types.OTHER)
    private RailAdditionalInfo railAdditionalInfo;
    
    @Column(name = "rail_onboarding_start_date")
    private LocalDateTime railOnboardingStartDate;
    
    @Column(name = "parent_user_id")
    private String parentUserId;
    
    @Deprecated
    @Column(name = "parent_conf", columnDefinition = "json")
    @org.hibernate.annotations.JdbcTypeCode(java.sql.Types.OTHER)
    private UserConfiguration parentConf;
    
    // Self-reference for parent user
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_user_ref_id")
    @JsonProperty("pu")
    private User parentUser;
    
    @Column(name = "can_be_emulated")
    private Boolean canBeEmulated;
    
    @Column(name = "user_conf", columnDefinition = "json")
    @org.hibernate.annotations.JdbcTypeCode(java.sql.Types.OTHER)
    private UserConfiguration userConf;
    
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "firstName", column = @Column(name = "profile_first_name")),
        @AttributeOverride(name = "lastName", column = @Column(name = "profile_last_name")),
        @AttributeOverride(name = "middleName", column = @Column(name = "profile_middle_name")),
        @AttributeOverride(name = "displayName", column = @Column(name = "profile_display_name")),
        @AttributeOverride(name = "gender", column = @Column(name = "profile_gender")),
        @AttributeOverride(name = "dateOfBirth", column = @Column(name = "profile_date_of_birth")),
        @AttributeOverride(name = "nationality", column = @Column(name = "profile_nationality")),
        @AttributeOverride(name = "profilePicture", column = @Column(name = "profile_picture")),
        @AttributeOverride(name = "bio", column = @Column(name = "profile_bio")),
        @AttributeOverride(name = "designation", column = @Column(name = "profile_designation")),
        @AttributeOverride(name = "department", column = @Column(name = "profile_department")),
        @AttributeOverride(name = "reportingManager", column = @Column(name = "profile_reporting_manager")),
        @AttributeOverride(name = "joiningDate", column = @Column(name = "profile_joining_date")),
        @AttributeOverride(name = "workLocation", column = @Column(name = "profile_work_location")),
        @AttributeOverride(name = "emergencyContactName", column = @Column(name = "profile_emergency_contact_name")),
        @AttributeOverride(name = "emergencyContactNumber", column = @Column(name = "profile_emergency_contact_number")),
        @AttributeOverride(name = "bloodGroup", column = @Column(name = "profile_blood_group"))
    })
    private UserProfile userProfile;
    
    @Column(name = "employee_id")
    private String employeeId;
    
    // Many-to-many relationship for user relations
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_relations",
        joinColumns = @JoinColumn(name = "user_id1"),
        inverseJoinColumns = @JoinColumn(name = "user_id2")
    )
    private Set<User> userRelations;
    
    @Column(name = "total_balance")
    private Double totalBalance;
    
    // Transient fields for API responses (not persisted)
    @Transient
    @JsonProperty("du")
    private DailyUsageInfo dailyUsageInfo;
    
    @Transient
    @JsonProperty("bs")
    private UserBalanceSummary balanceSummary;
    
    @Transient
    @JsonProperty("ds")
    private UserDuesSummary dueSummary;
    
    @Transient
    @JsonProperty("tt")
    private String tempToken;
    
    @Transient
    @JsonProperty("au")
    private Boolean assignUser;
    
    @Transient
    private Boolean showUnmaskedDetails;
    
    @Transient
    private String salesUserId;
    
    @Transient
    @Enumerated(EnumType.STRING)
    private RailApplicationStatus applStatus;
    
    @Transient
    @JsonProperty("lud")
    private List<UserDetails> linkedUserDetails;
    
    // Constructors, getters, setters are handled by Lombok @Data
    
    // Custom methods for backward compatibility
    public String getFirstName() {
        return userProfile != null ? userProfile.getFirstName() : null;
    }
    
    public String getLastName() {
        return userProfile != null ? userProfile.getLastName() : null;
    }
    
    public Boolean isEmailVerified() {
        return additionalInfo != null && additionalInfo.getCustomFields() != null 
            ? (Boolean) additionalInfo.getCustomFields().get("emailVerified") : false;
    }
    
    public Boolean isPanVerified() {
        return panInfo != null ? panInfo.getVerified() : false;
    }
    
    public Boolean isAadhaarVerified() {
        return additionalInfo != null && additionalInfo.getCustomFields() != null 
            ? (Boolean) additionalInfo.getCustomFields().get("aadhaarVerified") : false;
    }
    
    // Lifecycle callbacks
    @PrePersist
    protected void onCreate() {
        if (createdOn == null) {
            createdOn = LocalDateTime.now();
        }
        if (userId == null) {
            userId = java.util.UUID.randomUUID().toString();
        }
        if (status == null) {
            status = UserStatus.ACTIVE;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        processedOn = LocalDateTime.now();
    }
}

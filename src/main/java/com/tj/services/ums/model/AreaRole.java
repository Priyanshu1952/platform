package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Entity representing granular permissions for different functional areas.
 * This enables fine-grained access control across the system.
 */
@Entity
@Table(name = "area_roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AreaRole {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "role_code", nullable = false, unique = true)
    private String roleCode;
    
    @Column(name = "role_name", nullable = false)
    private String roleName;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Column(name = "functional_area", nullable = false)
    private String functionalArea;
    
    @Column(name = "created_on", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdOn;
    
    @Column(name = "active", nullable = false)
    private Boolean active = true;
    
    @ManyToMany(mappedBy = "areaRoles")
    private Set<UserGroup> userGroups;
    
    // Predefined role codes
    public static final String CMS_SERVICE = "CMS_SERVICE";
    public static final String CONFIG_EDIT = "CONFIG_EDIT";
    public static final String AIR_SUPPLIER = "AIR_SUPPLIER";
    public static final String BOOKING_REQUEST = "BOOKING_REQUEST";
    public static final String PROBE_VIEW = "PROBE_VIEW";
    public static final String AMENDMENT_PROCESSOR = "AMENDMENT_PROCESSOR";
    public static final String IMS_SERVICE = "IMS_SERVICE";
    public static final String USER_MANAGEMENT = "USER_MANAGEMENT";
    public static final String RELATIONSHIP_MANAGEMENT = "RELATIONSHIP_MANAGEMENT";
    public static final String GROUP_MANAGEMENT = "GROUP_MANAGEMENT";
    public static final String REPORT_VIEW = "REPORT_VIEW";
    public static final String SYSTEM_ADMIN = "SYSTEM_ADMIN";
    
    // Helper methods
    public boolean isActive() {
        return active != null && active;
    }
    
    public void deactivate() {
        this.active = false;
    }
    
    public void activate() {
        this.active = true;
    }
    
    @Override
    public String toString() {
        return "AreaRole{" +
                "id=" + id +
                ", roleCode='" + roleCode + '\'' +
                ", roleName='" + roleName + '\'' +
                ", functionalArea='" + functionalArea + '\'' +
                ", active=" + active +
                '}';
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AreaRole areaRole = (AreaRole) o;
        return roleCode != null ? roleCode.equals(areaRole.roleCode) : areaRole.roleCode == null;
    }
    
    @Override
    public int hashCode() {
        return roleCode != null ? roleCode.hashCode() : 0;
    }
} 
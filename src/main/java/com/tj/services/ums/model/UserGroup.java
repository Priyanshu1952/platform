package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Entity representing a group of users with associated permissions.
 * This enables role-based access control through area roles.
 */
@Entity
@Table(name = "user_groups")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserGroup {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "group_name", nullable = false, unique = true)
    private String groupName;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Column(name = "created_on", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdOn;
    
    @Column(name = "active", nullable = false)
    private Boolean active = true;
    
    @Column(name = "created_by")
    private String createdBy;
    
    // Many-to-many relationship with users
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_group_members",
        joinColumns = @JoinColumn(name = "group_id"),
        inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    private Set<User> members;
    
    // Many-to-many relationship with area roles
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_group_area_roles",
        joinColumns = @JoinColumn(name = "group_id"),
        inverseJoinColumns = @JoinColumn(name = "area_role_id")
    )
    private Set<AreaRole> areaRoles;
    
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
    
    public void addMember(User user) {
        if (members == null) {
            members = new java.util.HashSet<>();
        }
        members.add(user);
    }
    
    public void removeMember(User user) {
        if (members != null) {
            members.remove(user);
        }
    }
    
    public void addAreaRole(AreaRole areaRole) {
        if (areaRoles == null) {
            areaRoles = new java.util.HashSet<>();
        }
        areaRoles.add(areaRole);
    }
    
    public void removeAreaRole(AreaRole areaRole) {
        if (areaRoles != null) {
            areaRoles.remove(areaRole);
        }
    }
    
    public boolean hasMember(User user) {
        return members != null && members.contains(user);
    }
    
    public boolean hasAreaRole(AreaRole areaRole) {
        return areaRoles != null && areaRoles.contains(areaRole);
    }
    
    public boolean hasAreaRoleByCode(String roleCode) {
        return areaRoles != null && areaRoles.stream()
                .anyMatch(role -> role.getRoleCode().equals(roleCode));
    }
    
    @Override
    public String toString() {
        return "UserGroup{" +
                "id=" + id +
                ", groupName='" + groupName + '\'' +
                ", description='" + description + '\'' +
                ", active=" + active +
                ", memberCount=" + (members != null ? members.size() : 0) +
                ", areaRoleCount=" + (areaRoles != null ? areaRoles.size() : 0) +
                '}';
    }
} 
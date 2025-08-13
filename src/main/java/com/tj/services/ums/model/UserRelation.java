package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import com.tj.services.ums.annotation.ForbidInAPIRequest;

import java.time.LocalDateTime;

/**
 * Entity representing relationships between users with hierarchical depth and priority.
 * This replaces UserRelationship with more sophisticated features for complex organizational structures.
 */
@Entity
@Table(name = "user_relations", 
       uniqueConstraints = {
           @UniqueConstraint(columnNames = {"user_id1", "user_id2", "relationship_type"})
       })
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRelation {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @ForbidInAPIRequest(reason = "Auto-generated primary key")
    private Long id;
    
    @Column(name = "user_id1", nullable = false)
    private String userId1;
    
    @Column(name = "user_id2", nullable = false)
    private String userId2;
    
    @Column(name = "depth", nullable = false)
    private Integer depth;
    
    @Column(name = "priority", nullable = false)
    private Integer priority;
    
    @Column(name = "user_name1", nullable = false)
    @ForbidInAPIRequest(reason = "Server-managed denormalized field")
    private String userName1;
    
    @Column(name = "user_name2", nullable = false)
    @ForbidInAPIRequest(reason = "Server-managed denormalized field")
    private String userName2;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "relationship_type", nullable = false)
    private RelationshipType relationshipType;
    
    @Column(name = "created_on", nullable = false, updatable = false)
    @CreationTimestamp
    @ForbidInAPIRequest(reason = "Automatically set on creation")
    private LocalDateTime createdOn;
    
    @Column(name = "processed_on")
    @UpdateTimestamp
    @ForbidInAPIRequest(reason = "Server-managed processing timestamp")
    private LocalDateTime processedOn;
    
    @Column(name = "active", nullable = false)
    private Boolean active = true;
    
    @Column(name = "created_by")
    private String createdBy;
    
    @Column(name = "notes", columnDefinition = "TEXT")
    private String notes;
    
    // Helper methods
    public boolean involvesUser(String userId) {
        return userId1.equals(userId) || userId2.equals(userId);
    }
    
    public String getOtherUser(String userId) {
        if (userId1.equals(userId)) {
            return userId2;
        } else if (userId2.equals(userId)) {
            return userId1;
        }
        return null;
    }
    
    public String getOtherUserName(String userId) {
        if (userId1.equals(userId)) {
            return userName2;
        } else if (userId2.equals(userId)) {
            return userName1;
        }
        return null;
    }
    
    public boolean isActive() {
        return active != null && active;
    }
    
    public void deactivate() {
        this.active = false;
        this.processedOn = LocalDateTime.now();
    }
    
    public void activate() {
        this.active = true;
        this.processedOn = LocalDateTime.now();
    }
    
    public boolean isManagerEmployee() {
        return relationshipType == RelationshipType.MANAGER_EMPLOYEE;
    }
    
    public boolean isHierarchical() {
        return relationshipType == RelationshipType.MANAGER_EMPLOYEE || 
               relationshipType == RelationshipType.PARENT_CHILD ||
               relationshipType == RelationshipType.SUPERVISOR_SUBORDINATE;
    }
} 
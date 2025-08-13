package com.tj.services.ums.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * Entity representing relationships between users.
 * This enables hierarchical user management and access control.
 */
@Entity
@Table(name = "user_relationships", 
       uniqueConstraints = {
           @UniqueConstraint(columnNames = {"user_id1", "user_id2", "relationship_type"})
       })
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRelationship {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "user_id1", nullable = false)
    private String userId1;
    
    @Column(name = "user_id2", nullable = false)
    private String userId2;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "relationship_type", nullable = false)
    private RelationshipType relationshipType;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    
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
    
    public boolean isActive() {
        return active != null && active;
    }
    
    public void deactivate() {
        this.active = false;
        this.updatedAt = LocalDateTime.now();
    }
    
    public void activate() {
        this.active = true;
        this.updatedAt = LocalDateTime.now();
    }
} 
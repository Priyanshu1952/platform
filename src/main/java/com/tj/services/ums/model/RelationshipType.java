package com.tj.services.ums.model;

/**
 * Enum defining different types of user relationships in the system.
 * These relationships determine access control and business logic.
 */
public enum RelationshipType {
    
    /**
     * Manager-Employee relationship
     * Manager can view and manage employee data
     */
    MANAGER_EMPLOYEE("MANAGER_EMPLOYEE", "Manager can manage employee"),
    
    /**
     * Agent-Client relationship
     * Agent can access client information and perform actions on their behalf
     */
    AGENT_CLIENT("AGENT_CLIENT", "Agent can act on behalf of client"),
    
    /**
     * Partner-Associate relationship
     * Partners can share resources and collaborate
     */
    PARTNER_ASSOCIATE("PARTNER_ASSOCIATE", "Partners can collaborate"),
    
    /**
     * Parent-Child relationship
     * Parent can manage child user accounts
     */
    PARENT_CHILD("PARENT_CHILD", "Parent can manage child accounts"),
    
    /**
     * Team member relationship
     * Team members can view each other's basic information
     */
    TEAM_MEMBER("TEAM_MEMBER", "Team members can collaborate"),
    
    /**
     * Supervisor-Subordinate relationship
     * Supervisor can approve and manage subordinate actions
     */
    SUPERVISOR_SUBORDINATE("SUPERVISOR_SUBORDINATE", "Supervisor can approve subordinate actions"),
    
    /**
     * Mentor-Mentee relationship
     * Mentor can guide and support mentee
     */
    MENTOR_MENTEE("MENTOR_MENTEE", "Mentor can guide mentee"),
    
    /**
     * Peer relationship
     * Peers have equal access levels
     */
    PEER("PEER", "Equal access levels");
    
    private final String code;
    private final String description;
    
    RelationshipType(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }
    
    public static RelationshipType fromCode(String code) {
        for (RelationshipType type : values()) {
            if (type.code.equals(code)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown relationship type: " + code);
    }
    
    /**
     * Check if this relationship type is hierarchical (has depth and organizational structure)
     */
    public boolean isHierarchical() {
        return this == MANAGER_EMPLOYEE || 
               this == PARENT_CHILD || 
               this == SUPERVISOR_SUBORDINATE;
    }
} 
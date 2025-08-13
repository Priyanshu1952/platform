package com.tj.services.ums.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark fields that should not be modifiable through API requests.
 * These fields are typically server-managed and should only be set by the application logic.
 * 
 * Examples of fields that should be marked with this annotation:
 * - id (auto-generated primary key)
 * - userName1, userName2 (denormalized fields updated by server)
 * - createdOn (automatically set on creation)
 * - processedOn (automatically updated by server)
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface ForbidInAPIRequest {
    
    /**
     * Optional reason for why this field is forbidden in API requests.
     * This can be used for documentation and error messages.
     */
    String reason() default "Server-managed field";
    
    /**
     * Whether to log attempts to modify this field.
     * Default is true for security monitoring.
     */
    boolean logAttempts() default true;
} 
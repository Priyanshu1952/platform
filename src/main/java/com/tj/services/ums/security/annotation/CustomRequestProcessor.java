package com.tj.services.ums.security.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Custom annotation to declare required area-level roles for a controller or method.
 *
 * Example:
 * @CustomRequestProcessor(areaRole = {"CONFIG_EDIT", "BOOKING_REQUEST"})
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface CustomRequestProcessor {
    /**
     * Area roles required to access the endpoint. These map to Spring roles.
     * Values are compared against granted authorities with the ROLE_ prefix.
     */
    String[] areaRole() default {};
} 
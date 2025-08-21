package com.tj.services.ums.model;

import java.util.UUID;

public class EmulationContext {
    private static final ThreadLocal<EmulationSession> currentSession = new ThreadLocal<>();
    
    public static void setCurrentSession(EmulationSession session) {
        currentSession.set(session);
    }
    
    public static EmulationSession getCurrentSession() {
        return currentSession.get();
    }
    
    public static void clear() {
        currentSession.remove();
    }
    
    public static boolean isEmulationActive() {
        return currentSession.get() != null;
    }
    
    public static UUID getEmulatedUserId() {
        EmulationSession session = currentSession.get();
        return session != null ? session.getTargetUserId() : null;
    }
    
    public static UUID getEmulatingUserId() {
        EmulationSession session = currentSession.get();
        return session != null ? session.getEmulatingUserId() : null;
    }
    
    public static boolean isEmulatedSession() {
        return isEmulationActive();
    }
    
    public static String getEmulatedBy() {
        EmulationSession session = currentSession.get();
        return session != null ? session.getEmulatingUserId().toString() : null;
    }
} 
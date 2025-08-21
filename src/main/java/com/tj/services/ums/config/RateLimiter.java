package com.tj.services.ums.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class RateLimiter {

    @Value("${app.rate-limit.enabled:true}")
    private boolean rateLimitEnabled;

    private final ConcurrentMap<String, SimpleRateLimiter> limiters = new ConcurrentHashMap<>();

    public boolean isBlocked(String key) {
        if (!rateLimitEnabled) {
            return false; // Rate limiting disabled
        }
        SimpleRateLimiter limiter = limiters.computeIfAbsent(key, k -> new SimpleRateLimiter(10, 60)); // 10 requests per 60 seconds
        return !limiter.isAllowed();
    }

    private static class SimpleRateLimiter {
        private final int maxRequests;
        private final long intervalMillis;
        private final ConcurrentMap<Long, Integer> requests = new ConcurrentHashMap<>();

        SimpleRateLimiter(int maxRequests, int intervalSeconds) {
            this.maxRequests = maxRequests;
            this.intervalMillis = intervalSeconds * 1000L;
        }

        boolean isAllowed() {
            long now = System.currentTimeMillis();
            long windowStart = now - intervalMillis;

            requests.entrySet().removeIf(entry -> entry.getKey() < windowStart);

            int currentRequests = requests.values().stream().mapToInt(Integer::intValue).sum();

            if (currentRequests < maxRequests) {
                requests.merge(now, 1, Integer::sum);
                return true;
            } else {
                return false;
            }
        }
    }
}

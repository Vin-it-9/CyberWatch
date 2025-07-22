package org.cyberwatch.detector;

import org.cyberwatch.service.BaseDetectionService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class BruteForceDetector extends BaseDetectionService implements AttackDetector {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long CLEANUP_INTERVAL = 300000;

    private final ConcurrentHashMap<String, AtomicInteger> failedAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastAttemptTime = new ConcurrentHashMap<>();

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        String uri = request.getRequestURI().toLowerCase();
        if (!isLoginEndpoint(uri)) {
            return false;
        }
        return detectFailedLogin(clientIP, request);
    }

    public boolean detectFailedLogin(String clientIP, HttpServletRequest request) {
        String key = clientIP;
        AtomicInteger attempts = failedAttempts.computeIfAbsent(key, k -> new AtomicInteger(0));
        lastAttemptTime.put(key, System.currentTimeMillis());

        int currentAttempts = attempts.incrementAndGet();

        if (currentAttempts >= MAX_FAILED_ATTEMPTS) {
            logAttack("BRUTE_FORCE", clientIP,
                    String.format("Multiple failed login attempts: %d attempts", currentAttempts),
                    request);
            return true;
        }

        return false;
    }

    public void recordSuccessfulLogin(String clientIP) {
        failedAttempts.remove(clientIP);
        lastAttemptTime.remove(clientIP);
    }

    private boolean isLoginEndpoint(String uri) {
        return uri.contains("login") || uri.contains("auth") || uri.contains("signin");
    }

    @Override
    public String getAttackType() {
        return "BRUTE_FORCE";
    }

    @Scheduled(fixedRate = CLEANUP_INTERVAL)
    public void cleanup() {
        long currentTime = System.currentTimeMillis();
        lastAttemptTime.entrySet().removeIf(entry ->
                currentTime - entry.getValue() > CLEANUP_INTERVAL * 2);
        failedAttempts.keySet().retainAll(lastAttemptTime.keySet());
    }
}

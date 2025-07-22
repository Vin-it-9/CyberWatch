package org.cyberwatch.detector;

import org.cyberwatch.service.BaseDetectionService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class DDoSDetector extends BaseDetectionService implements AttackDetector {

    private static final int DDOS_THRESHOLD = 100; // requests per minute
    private static final int TIME_WINDOW_SECONDS = 60;

    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> firstRequestTime = new ConcurrentHashMap<>();

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        long currentTime = System.currentTimeMillis();

        // Initialize or get existing counters
        AtomicInteger count = requestCounts.computeIfAbsent(clientIP, k -> new AtomicInteger(0));
        Long firstRequest = firstRequestTime.computeIfAbsent(clientIP, k -> currentTime);

        // Reset counter if time window has passed
        if (currentTime - firstRequest > TIME_WINDOW_SECONDS * 1000) {
            count.set(0);
            firstRequestTime.put(clientIP, currentTime);
        }

        int currentCount = count.incrementAndGet();

        if (currentCount > DDOS_THRESHOLD) {
            logAttack("DDOS", clientIP,
                    String.format("High request frequency: %d requests in %d seconds",
                            currentCount, TIME_WINDOW_SECONDS), request);
            return true;
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "DDOS";
    }

    @Scheduled(fixedRate = 300000) // Clean up every 5 minutes
    public void cleanup() {
        long currentTime = System.currentTimeMillis();
        firstRequestTime.entrySet().removeIf(entry ->
                currentTime - entry.getValue() > TIME_WINDOW_SECONDS * 2 * 1000);
        requestCounts.keySet().retainAll(firstRequestTime.keySet());
    }
}

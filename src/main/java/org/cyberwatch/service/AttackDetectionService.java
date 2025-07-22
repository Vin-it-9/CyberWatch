package org.cyberwatch.service;


import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.cyberwatch.detector.SecurityMetricsRecorder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AttackDetectionService {

    @Autowired
    private SecurityMetricsRecorder recorder;

    @Autowired
    private CachedAttackPatternService patternService;

    @Bulkhead(name = "attackDetectionBulkhead")
    @RateLimiter(name = "attackDetectionRateLimiter")
    public String detect(String payload, String clientIp) {

        try {
            boolean isKnownAttack = patternService.isKnownAttackPattern(payload);

            if (isKnownAttack) {
                recorder.incrementKnown();
                System.out.println("[ATTACK DETECTED] Known attack pattern from " + clientIp + ": " + payload);
                return "⚠SECURITY ALERT: Known attack pattern detected from " + clientIp +
                        ". Attack type: " + getAttackType(payload) + ". Payload: " + payload.substring(0, Math.min(50, payload.length()));
            }

            if (isSuspiciousPattern(payload)) {
                recorder.incrementSuspicious();
                System.out.println("[SUSPICIOUS ACTIVITY] Potential attack from " + clientIp + ": " + payload);
                return "SECURITY WARNING: Suspicious pattern detected from " + clientIp +
                        ". Please review: " + payload.substring(0, Math.min(30, payload.length()));
            }

            recorder.incrementClean();
            return "Payload looks clean from " + clientIp + ". No threats detected.";

        } catch (Exception e) {
            System.err.println("Error in attack detection: " + e.getMessage());
            recorder.incrementError();
            return "Error analyzing payload from " + clientIp + ". Please try again.";
        }
    }

    private boolean isSuspiciousPattern(String payload) {
        if (payload == null || payload.trim().isEmpty()) {
            return false;
        }

        String lowercasePayload = payload.toLowerCase();

        // Check for various suspicious patterns
        return lowercasePayload.contains("script") ||
                lowercasePayload.contains("javascript") ||
                lowercasePayload.contains("eval(") ||
                lowercasePayload.contains("document.cookie") ||
                lowercasePayload.contains("alert(") ||
                lowercasePayload.contains("onload") ||
                lowercasePayload.contains("onerror") ||
                lowercasePayload.length() > 1000;
    }

    private String getAttackType(String payload) {
        String lowercasePayload = payload.toLowerCase();

        if (lowercasePayload.contains("union") && lowercasePayload.contains("select")) {
            return "SQL Injection";
        }
        if (lowercasePayload.contains("<script") || lowercasePayload.contains("javascript:")) {
            return "XSS (Cross-Site Scripting)";
        }
        if (lowercasePayload.contains("../") || lowercasePayload.contains("..\\")) {
            return "Directory Traversal";
        }
        if (lowercasePayload.contains("cmd") || lowercasePayload.contains("exec")) {
            return "Command Injection";
        }

        return "Unknown Attack Pattern";
    }
}

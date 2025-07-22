package org.cyberwatch.service;

import org.cyberwatch.detector.SecurityMetricsRecorder;
import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.hibernate.service.spi.InjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class BaseDetectionService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    public SecurityMetricsRecorder securityMetricsRecorder;

    // In-memory cache for tracking request counts by IP
    private final ConcurrentHashMap<String, AtomicLong> ipRequestCounts = new ConcurrentHashMap<>();

    protected void logAttack(String attackType, String sourceIp, String description,
                             HttpServletRequest request) {
        AttackLog log = new AttackLog(attackType, sourceIp, description);
        log.setTargetEndpoint(request.getRequestURI());
        log.setRequestMethod(request.getMethod());
        log.setUserAgent(request.getHeader("User-Agent"));

        if ("POST".equalsIgnoreCase(request.getMethod()) ||
                "PUT".equalsIgnoreCase(request.getMethod())) {
            log.setRequestPayload(getRequestPayload(request));
        }

        log.setSeverity(determineSeverity(attackType));
        attackLogRepository.save(log);
        eventPublisher.publishEvent(log);

        System.out.println("[SECURITY ALERT] " + attackType + " detected from " +
                sourceIp + ": " + description);
    }

    protected String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }

        return request.getRemoteAddr();
    }

    protected void incrementRequestCount(String ip) {
        ipRequestCounts.computeIfAbsent(ip, k -> new AtomicLong()).incrementAndGet();
    }

    protected long getRequestCount(String ip) {
        AtomicLong count = ipRequestCounts.get(ip);
        return count != null ? count.get() : 0;
    }

    protected void resetRequestCount(String ip) {
        ipRequestCounts.remove(ip);
    }

    private AttackLog.Severity determineSeverity(String attackType) {
        switch (attackType.toUpperCase()) {
            case "DDOS":
            case "SQL_INJECTION":
                return AttackLog.Severity.CRITICAL;
            case "XSS":
            case "BRUTE_FORCE":
                return AttackLog.Severity.HIGH;
            case "PORT_SCAN":
            case "DIRECTORY_TRAVERSAL":
                return AttackLog.Severity.MEDIUM;
            default:
                return AttackLog.Severity.LOW;
        }
    }

    private String getRequestPayload(HttpServletRequest request) {
        try {
            return request.getParameterMap().toString();
        } catch (Exception e) {
            return "Unable to capture payload";
        }
    }
}

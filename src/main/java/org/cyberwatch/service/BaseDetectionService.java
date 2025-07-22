package org.cyberwatch.service;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class BaseDetectionService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private IPBlockingService ipBlockingService;

    private final ConcurrentHashMap<String, AtomicLong> ipRequestCounts = new ConcurrentHashMap<>();


    protected AttackLog logAttack(String attackType, String sourceIp, String description,
                                  HttpServletRequest request) {

        AttackLog log = new AttackLog(attackType, sourceIp, description);
        log.setTargetEndpoint(request.getRequestURI());
        log.setRequestMethod(request.getMethod());
        log.setUserAgent(request.getHeader("User-Agent"));

        if ("POST".equalsIgnoreCase(request.getMethod()) ||
                "PUT".equalsIgnoreCase(request.getMethod())) {
            log.setRequestPayload(getRequestPayload(request));
        }

        AttackLog.Severity severity = calculateAdvancedSeverity(attackType, sourceIp, request);
        log.setSeverity(severity);

        boolean shouldBlock = shouldBlockAttack(attackType, severity, sourceIp);
        log.setBlocked(shouldBlock);

        if (shouldBlock) {
            ipBlockingService.blockIP(sourceIp,
                    "Attack detected: " + attackType + " - " + description,
                    severity,
                    request.getHeader("User-Agent"));
        }

        AttackLog savedLog = attackLogRepository.save(log);
        eventPublisher.publishEvent(savedLog);

        String blockStatus = shouldBlock ? "🚫 BLOCKED" : "📝 LOGGED";
        System.out.println(String.format(
                "%s [%s] %s from %s (%s) - %s",
                blockStatus, severity, attackType, sourceIp,
                request.getHeader("User-Agent") != null ?
                        request.getHeader("User-Agent").substring(0, Math.min(30, request.getHeader("User-Agent").length())) :
                        "Unknown",
                description
        ));

        return savedLog;
    }


    private AttackLog.Severity calculateAdvancedSeverity(String attackType, String sourceIp, HttpServletRequest request) {
        int severityScore = 0;

        severityScore += getBaseAttackSeverity(attackType);
        severityScore += calculateFrequencyBonus(sourceIp);
        severityScore += analyzeRequestPatterns(request);
        severityScore += detectEvasionTechniques(request);

        if (severityScore >= 80) return AttackLog.Severity.CRITICAL;
        if (severityScore >= 60) return AttackLog.Severity.HIGH;
        if (severityScore >= 40) return AttackLog.Severity.MEDIUM;
        return AttackLog.Severity.LOW;
    }

    private int getBaseAttackSeverity(String attackType) {
        return switch (attackType) {
            case "SQL_INJECTION" -> 70;
            case "COMMAND_INJECTION" -> 80;
            case "XXE" -> 75;
            case "SSRF" -> 65;
            case "FILE_UPLOAD_ATTACK" -> 70;
            case "LDAP_INJECTION" -> 60;
            case "XSS" -> 50;
            case "BRUTE_FORCE" -> 45;
            case "CSRF" -> 40;
            case "LOG_INJECTION" -> 35;
            case "DIRECTORY_TRAVERSAL" -> 40;
            case "DDOS" -> 60;
            default -> 25;
        };
    }

    private int calculateFrequencyBonus(String sourceIp) {

        LocalDateTime lastHour = LocalDateTime.now().minusHours(1);
        long recentAttacks = attackLogRepository.findBySourceIpAndDetectedAtAfter(sourceIp, lastHour).size();

        if (recentAttacks >= 10) return 30;
        if (recentAttacks >= 5) return 20;
        if (recentAttacks >= 2) return 10;
        return 0;
    }

    private int analyzeRequestPatterns(HttpServletRequest request) {
        int patternScore = 0;
        String queryString = request.getQueryString();
        String userAgent = request.getHeader("User-Agent");

        if (queryString != null && queryString.length() > 500) patternScore += 15;

        if (userAgent != null) {
            String ua = userAgent.toLowerCase();
            if (ua.contains("sqlmap") || ua.contains("nmap") ||
                    ua.contains("nikto") || ua.contains("curl")) {
                patternScore += 25;
            }
        }

        if (queryString != null &&
                (queryString.contains("%") && queryString.split("%").length > 5)) {
            patternScore += 10;
        }

        return patternScore;
    }

    private int detectEvasionTechniques(HttpServletRequest request) {
        int evasionScore = 0;
        String queryString = request.getQueryString();

        if (queryString != null) {
            if (queryString.contains("%25")) evasionScore += 15;
            if (queryString.contains("\\u")) evasionScore += 10;
            if (queryString.contains("/*") && queryString.contains("*/")) evasionScore += 10;
        }

        return evasionScore;
    }


    private boolean shouldBlockAttack(String attackType, AttackLog.Severity severity, String sourceIp) {

        if (severity == AttackLog.Severity.CRITICAL) return true;

        if (severity == AttackLog.Severity.HIGH) {
            LocalDateTime lastHour = LocalDateTime.now().minusHours(1);
            long recentAttacks = attackLogRepository.findBySourceIpAndDetectedAtAfter(sourceIp, lastHour).size();
            return recentAttacks >= 3;
        }

        return attackType.equals("BRUTE_FORCE") || attackType.equals("SQL_INJECTION");
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

    private String getRequestPayload(HttpServletRequest request) {
        try {
            return request.getParameterMap().toString();
        } catch (Exception e) {
            return "Unable to capture payload: " + e.getMessage();
        }
    }
}

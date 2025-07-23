package org.cyberwatch.filter;

import org.cyberwatch.config.DetectionConfig;
import org.cyberwatch.detector.AttackDetector;
import org.cyberwatch.service.IPBlockingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Component
@Order(1)
public class SecurityMonitoringFilter implements Filter {

    @Autowired
    private List<AttackDetector> attackDetectors;

    @Autowired
    private IPBlockingService ipBlockingService;

    @Autowired
    private DetectionConfig detectionConfig;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("🛡️ Security Monitoring Filter initialized with " +
                attackDetectors.size() + " detectors");
        System.out.println("🔧 Real blocking mode: " + (detectionConfig.isEnableRealBlocking() ? "ENABLED" : "DISABLED"));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String clientIP = getClientIP(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        String requestURI = httpRequest.getRequestURI();

        if (shouldSkipMonitoring(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        boolean blockingEnabled = detectionConfig.isEnableRealBlocking();
        String mode = blockingEnabled ? "PRODUCTION" : "TESTING";

        if (blockingEnabled && ipBlockingService.isIPBlocked(clientIP)) {
            blockRequest(httpRequest, httpResponse, clientIP, "IP is currently blocked due to previous attacks");
            return;
        } else if (!blockingEnabled && ipBlockingService.isBlocked(clientIP)) {
            System.out.println("🧪 " + mode + " MODE: IP " + clientIP + " would be blocked but continuing for testing");
        }

        if (blockingEnabled && ipBlockingService.isAgentBlocked(clientIP, userAgent)) {
            blockRequest(httpRequest, httpResponse, clientIP, "IP + User-Agent combination is blocked");
            return;
        } else if (!blockingEnabled && ipBlockingService.isAgentBlocked(clientIP, userAgent)) {
            System.out.println("🧪 " + mode + " MODE: IP+Agent " + clientIP + " would be blocked but continuing for testing");
        }

        boolean attackDetected = false;
        String detectedAttackType = "";
        int attacksInThisRequest = 0;

        for (AttackDetector detector : attackDetectors) {
            if (detector.isEnabled()) {
                try {
                    boolean detected = detector.detectAttack(httpRequest, clientIP);
                    if (detected) {
                        attackDetected = true;
                        detectedAttackType = detector.getAttackType();
                        attacksInThisRequest++;

                        System.out.println("🚨 ATTACK DETECTED (" + mode + " MODE): " + detector.getAttackType() +
                                " from " + clientIP + " via " +
                                (userAgent != null ? userAgent.substring(0, Math.min(30, userAgent.length())) : "Unknown"));

                        if (shouldImmediatelyBlock(detector.getAttackType())) {
                            ipBlockingService.blockIP(clientIP,
                                    "Severe attack detected: " + detector.getAttackType(),
                                    getSeverityForAttack(detector.getAttackType()),
                                    userAgent);

                            if (blockingEnabled) {
                                blockRequest(httpRequest, httpResponse, clientIP,
                                        "Severe attack detected. Access blocked immediately.");
                                return;
                            } else {
                                System.out.println("🧪 " + mode + " MODE: Would immediately block " + clientIP +
                                        " for severe attack: " + detector.getAttackType() +
                                        " (Duration: " + getBlockDurationForSeverity(getSeverityForAttack(detector.getAttackType())) + " minutes)");
                            }
                        } else {
                            boolean wouldBeBlocked = ipBlockingService.markSuspicious(clientIP, userAgent, detector.getAttackType());

                            if (wouldBeBlocked) {
                                if (blockingEnabled) {
                                    blockRequest(httpRequest, httpResponse, clientIP,
                                            "Multiple attacks detected. Access blocked.");
                                    return;
                                } else {
                                    System.out.println("🧪 " + mode + " MODE: Would block " + clientIP +
                                            " after multiple suspicious activities for: " + detector.getAttackType());
                                }
                            } else {
                                if (!blockingEnabled) {
                                    System.out.println("🧪 " + mode + " MODE: Marked " + clientIP +
                                            " as suspicious for: " + detector.getAttackType());
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("❌ Error in detector " + detector.getClass().getSimpleName() +
                            ": " + e.getMessage());
                }
            }
        }

        if (attackDetected) {
            if (blockingEnabled) {
                System.out.println("⚠️ ATTACK LOGGED (" + mode + " MODE): " + attacksInThisRequest + " attack(s) detected from " + clientIP +
                        " - Request processed with security monitoring");
            } else {
                System.out.println("⚠️ ATTACK LOGGED (" + mode + " MODE): " + attacksInThisRequest + " attack(s) detected from " + clientIP +
                        " - All attacks logged, blocking disabled for testing");
            }
        }

        chain.doFilter(request, response);
    }

    private void blockRequest(HttpServletRequest request, HttpServletResponse response, String clientIP, String reason) throws IOException {

        String userAgent = request.getHeader("User-Agent");
        String accept = request.getHeader("Accept");

        boolean isApiRequest = (accept != null && accept.contains("application/json")) ||
                (userAgent != null && (userAgent.contains("curl") ||
                        userAgent.contains("Postman") ||
                        userAgent.contains("HTTPie") ||
                        userAgent.contains("python-requests") ||
                        userAgent.contains("Java/") ||
                        userAgent.contains("okhttp")));

        if (isApiRequest) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setHeader("X-Security-Block", "true");

            String jsonResponse = String.format(
                    "{" +
                            "\"error\": \"Access Denied\"," +
                            "\"message\": \"%s\"," +
                            "\"blocked_ip\": \"%s\"," +
                            "\"timestamp\": \"%s\"," +
                            "\"mode\": \"%s\"," +
                            "\"contact\": \"Contact administrator if you believe this is an error\"" +
                            "}",
                    reason, clientIP, java.time.LocalDateTime.now(),
                    detectionConfig.isEnableRealBlocking() ? "PRODUCTION" : "TESTING"
            );

            response.getWriter().write(jsonResponse);
            response.getWriter().flush();

        } else {
            try {
                String redirectUrl = String.format("/access-denied?ip=%s&reason=%s&timestamp=%s",
                        java.net.URLEncoder.encode(clientIP, "UTF-8"),
                        java.net.URLEncoder.encode(reason, "UTF-8"),
                        java.net.URLEncoder.encode(java.time.LocalDateTime.now().toString(), "UTF-8")
                );

                response.sendRedirect(redirectUrl);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                String fallbackJson = String.format(
                        "{\"error\":\"Access Denied\",\"message\":\"%s\",\"blocked_ip\":\"%s\"}",
                        reason, clientIP
                );
                response.getWriter().write(fallbackJson);
                response.getWriter().flush();
            }
        }

        System.out.println("🚫 BLOCKED REQUEST: " + clientIP + " - " + reason +
                " (Client: " + (isApiRequest ? "API" : "Browser") + ")");
    }


    private boolean shouldImmediatelyBlock(String attackType) {
        return attackType.equals("SQL_INJECTION") ||
                attackType.equals("COMMAND_INJECTION") ||
                attackType.equals("XXE") ||
                attackType.equals("BRUTE_FORCE");
    }

    private org.cyberwatch.model.AttackLog.Severity getSeverityForAttack(String attackType) {
        return switch (attackType) {
            case "SQL_INJECTION", "COMMAND_INJECTION", "XXE" -> org.cyberwatch.model.AttackLog.Severity.CRITICAL;
            case "XSS", "BRUTE_FORCE", "CSRF", "SSRF" -> org.cyberwatch.model.AttackLog.Severity.HIGH;
            case "DIRECTORY_TRAVERSAL", "FILE_UPLOAD_ATTACK", "LDAP_INJECTION" -> org.cyberwatch.model.AttackLog.Severity.MEDIUM;
            case "LOG_INJECTION", "DDOS" -> org.cyberwatch.model.AttackLog.Severity.LOW;
            default -> org.cyberwatch.model.AttackLog.Severity.LOW;
        };
    }


    private int getBlockDurationForSeverity(org.cyberwatch.model.AttackLog.Severity severity) {
        return switch (severity) {
            case CRITICAL -> 120;
            case HIGH -> 60;
            case MEDIUM -> 30;
            case LOW -> 15;
        };
    }


    private String getClientIP(HttpServletRequest request) {
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


    private boolean shouldSkipMonitoring(String requestURI) {
        return requestURI.startsWith("/actuator") ||
                requestURI.startsWith("/swagger-ui") ||
                requestURI.startsWith("/v3/api-docs") ||
                requestURI.startsWith("/css/") ||
                requestURI.startsWith("/js/") ||
                requestURI.startsWith("/images/") ||
                requestURI.startsWith("/favicon.ico") ||
                requestURI.startsWith("/webjars/") ||
                requestURI.startsWith("/access-denied") ||
                requestURI.startsWith("/error/");
    }

    @Override
    public void destroy() {
        System.out.println("🛡️ Security Monitoring Filter destroyed");
    }
}

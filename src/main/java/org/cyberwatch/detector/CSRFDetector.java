package org.cyberwatch.detector;

import org.cyberwatch.service.BaseDetectionService;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

@Component
public class CSRFDetector extends BaseDetectionService implements AttackDetector {

    private final List<String> statefulMethods = Arrays.asList("POST", "PUT", "DELETE", "PATCH");

    private final List<String> criticalEndpoints = Arrays.asList(
            "/transfer", "/payment", "/delete", "/admin", "/user", "/account",
            "/password", "/email", "/settings", "/withdraw", "/deposit"
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        String method = request.getMethod();
        String referer = request.getHeader("Referer");
        String origin = request.getHeader("Origin");
        String requestURI = request.getRequestURI().toLowerCase();

        if (!statefulMethods.contains(method)) {
            return false;
        }

        String csrfToken = request.getHeader("X-CSRF-Token");
        String csrfParam = request.getParameter("_token");
        String csrfCookie = getCsrfTokenFromCookies(request);

        boolean hasCsrfProtection = (csrfToken != null) || (csrfParam != null) || (csrfCookie != null);

        boolean suspiciousReferer = isSuspiciousReferer(request, referer, origin);

        boolean isCriticalEndpoint = criticalEndpoints.stream()
                .anyMatch(endpoint -> requestURI.contains(endpoint));

        if (isCriticalEndpoint && (!hasCsrfProtection || suspiciousReferer)) {
            String reason = "";
            if (!hasCsrfProtection) {
                reason = "Missing CSRF protection on critical endpoint";
            }
            if (suspiciousReferer) {
                reason += (reason.isEmpty() ? "" : " + ") + "Suspicious referer/origin";
            }

            logAttack("CSRF", clientIP,
                    String.format("Potential CSRF attack on %s %s - %s", method, requestURI, reason),
                    request);
            return true;
        }

        return false;
    }

    private boolean isSuspiciousReferer(HttpServletRequest request, String referer, String origin) {
        String serverName = request.getServerName();
        String scheme = request.getScheme();
        int port = request.getServerPort();

        String expectedHost = scheme + "://" + serverName;
        if ((scheme.equals("http") && port != 80) || (scheme.equals("https") && port != 443)) {
            expectedHost += ":" + port;
        }

        if (referer != null && !referer.startsWith(expectedHost)) {
            return true;
        }

        if (origin != null && !origin.equals(expectedHost)) {
            return true;
        }

        return referer == null && origin == null;
    }

    private String getCsrfTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (cookie.getName().toLowerCase().contains("csrf") ||
                        cookie.getName().toLowerCase().contains("xsrf")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    @Override
    public String getAttackType() {
        return "CSRF";
    }
}

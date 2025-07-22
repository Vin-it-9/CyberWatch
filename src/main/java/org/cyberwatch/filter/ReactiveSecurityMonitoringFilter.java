//package org.cyberwatch.filter;
//
//
//import org.cyberwatch.detector.AttackDetector;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.core.annotation.Order;
//import org.springframework.stereotype.Component;
//
//import jakarta.servlet.*;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.List;
//
//@Component
//@Order(1)
//public class ReactiveSecurityMonitoringFilter implements Filter {
//
//    @Autowired
//    private List<AttackDetector> attackDetectors;
//
//    @Override
//    public void init(FilterConfig filterConfig) throws ServletException {
//        System.out.println("Security Monitoring Filter initialized with " +
//                attackDetectors.size() + " detectors");
//    }
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response,
//                         FilterChain chain) throws IOException, ServletException {
//
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        HttpServletResponse httpResponse = (HttpServletResponse) response;
//
//        String clientIP = getClientIP(httpRequest);
//        String requestURI = httpRequest.getRequestURI();
//
//        // Skip monitoring for certain paths
//        if (shouldSkipMonitoring(requestURI)) {
//            chain.doFilter(request, response);
//            return;
//        }
//
//        boolean attackDetected = false;
//
//        // Run all enabled detectors
//        for (AttackDetector detector : attackDetectors) {
//            if (detector.isEnabled()) {
//                try {
//                    boolean detected = detector.detectAttack(httpRequest, clientIP);
//                    if (detected) {
//                        attackDetected = true;
//                        System.out.println("[SECURITY ALERT] " + detector.getAttackType() +
//                                " detected from " + clientIP);
//                    }
//                } catch (Exception e) {
//                    System.err.println("Error in detector " + detector.getClass().getSimpleName() +
//                            ": " + e.getMessage());
//                }
//            }
//        }
//
//        // Continue processing
//        chain.doFilter(request, response);
//    }
//
//    private String getClientIP(HttpServletRequest request) {
//        String xForwardedFor = request.getHeader("X-Forwarded-For");
//        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
//            return xForwardedFor.split(",")[0].trim();
//        }
//
//        String xRealIP = request.getHeader("X-Real-IP");
//        if (xRealIP != null && !xRealIP.isEmpty()) {
//            return xRealIP;
//        }
//
//        return request.getRemoteAddr();
//    }
//
//    private boolean shouldSkipMonitoring(String requestURI) {
//        return requestURI.startsWith("/actuator") ||
//                requestURI.startsWith("/swagger-ui") ||
//                requestURI.startsWith("/v3/api-docs") ||
//                requestURI.startsWith("/css/") ||
//                requestURI.startsWith("/js/") ||
//                requestURI.startsWith("/images/") ||
//                requestURI.startsWith("/favicon.ico");
//    }
//
//    @Override
//    public void destroy() {
//        System.out.println("Security Monitoring Filter destroyed");
//    }
//}

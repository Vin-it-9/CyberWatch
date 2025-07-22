package org.cyberwatch.controller;


import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.cyberwatch.service.IPBlockingService;
import org.cyberwatch.service.SecurityMetricsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/security")
@Tag(name = "Security Dashboard", description = "Real-time security monitoring and control")
public class SecurityDashboardController {

    @Autowired
    private IPBlockingService ipBlockingService;

    @Autowired
    private SecurityMetricsService securityMetricsService;

    @GetMapping("/dashboard")
    @Operation(summary = "Get comprehensive security dashboard data")
    public Map<String, Object> getDashboard() {
        Map<String, Object> dashboard = new HashMap<>();

        // Security metrics
        dashboard.put("metrics", securityMetricsService.getCurrentMetrics());
        dashboard.put("hourlyStats", securityMetricsService.getHourlyAttackStats());
        dashboard.put("severityStats", securityMetricsService.getAttackSeverityStats());

        // Blocking statistics
        dashboard.put("blockingStats", ipBlockingService.getBlockingStats());
        dashboard.put("blockedIPs", ipBlockingService.getCurrentlyBlockedIPs());

        // System status
        Map<String, Object> systemStatus = new HashMap<>();
        systemStatus.put("status", "ACTIVE");
        systemStatus.put("protectionLevel", "MAXIMUM");
        systemStatus.put("realTimeBlocking", "ENABLED");
        systemStatus.put("lastUpdated", java.time.LocalDateTime.now());

        dashboard.put("systemStatus", systemStatus);

        return dashboard;
    }

    @PostMapping("/unblock/{ip}")
    @Operation(summary = "Manually unblock an IP address")
    public Map<String, Object> unblockIP(@PathVariable String ip) {
        boolean success = ipBlockingService.unblockIP(ip);

        Map<String, Object> response = new HashMap<>();
        response.put("success", success);
        response.put("message", success ? "IP unblocked successfully" : "IP was not blocked");
        response.put("ip", ip);
        response.put("timestamp", java.time.LocalDateTime.now());

        return response;
    }

    @GetMapping("/blocked-ips")
    @Operation(summary = "Get list of currently blocked IPs")
    public Map<String, Object> getBlockedIPs() {
        return Map.of(
                "blockedIPs", ipBlockingService.getCurrentlyBlockedIPs(),
                "blockingStats", ipBlockingService.getBlockingStats()
        );
    }
}


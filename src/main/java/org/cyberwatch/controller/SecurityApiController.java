package org.cyberwatch.controller;


import io.swagger.v3.oas.annotations.tags.Tag;
import org.cyberwatch.model.AttackLog;
import org.cyberwatch.model.SecurityMetrics;
import org.cyberwatch.service.AlertService;
import org.cyberwatch.service.SecurityMetricsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/security")
@CrossOrigin(origins = "*")
@Tag(name = "2. Security Dashboard API", description = "APIs to fetch security data for dashboards and analytics.")
public class SecurityApiController {

    @Autowired
    private AlertService alertService;

    @Autowired
    private SecurityMetricsService metricsService;

    @GetMapping("/alerts")
    public ResponseEntity<List<AttackLog>> getRecentAlerts(
            @RequestParam(defaultValue = "50") int limit) {
        List<AttackLog> alerts = alertService.getRecentAlerts(limit);
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/alerts/type/{attackType}")
    public ResponseEntity<List<AttackLog>> getAlertsByType(@PathVariable String attackType) {
        List<AttackLog> alerts = alertService.getAlertsByType(attackType.toUpperCase());
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/alerts/ip/{sourceIp}")
    public ResponseEntity<List<AttackLog>> getAlertsByIP(@PathVariable String sourceIp) {
        List<AttackLog> alerts = alertService.getAlertsByIP(sourceIp);
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/alerts/timerange")
    public ResponseEntity<List<AttackLog>> getAlertsInTimeRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
        List<AttackLog> alerts = alertService.getAlertsInTimeRange(start, end);
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/metrics")
    public ResponseEntity<SecurityMetrics> getSecurityMetrics() {
        SecurityMetrics metrics = metricsService.getCurrentMetrics();
        return ResponseEntity.ok(metrics);
    }

    @GetMapping("/metrics/hourly")
    public ResponseEntity<Map<String, Object>> getHourlyStats() {
        Map<String, Object> stats = metricsService.getHourlyAttackStats();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/metrics/severity")
    public ResponseEntity<Map<String, Object>> getSeverityStats() {
        Map<String, Object> stats = metricsService.getAttackSeverityStats();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/trends")
    public ResponseEntity<List<Map<String, Object>>> getAttackTrends() {
        List<Map<String, Object>> trends = metricsService.getAttackTrendData();
        return ResponseEntity.ok(trends);
    }

    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboardData() {
        Map<String, Object> dashboard = new HashMap<>();

        SecurityMetrics metrics = metricsService.getCurrentMetrics();
        dashboard.put("metrics", metrics);
        dashboard.put("recentAlerts", alertService.getRecentAlerts(10));
        dashboard.put("hourlyStats", metricsService.getHourlyAttackStats());
        dashboard.put("severityStats", metricsService.getAttackSeverityStats());
        dashboard.put("trends", metricsService.getAttackTrendData());

        return ResponseEntity.ok(dashboard);
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "online");
        status.put("timestamp", System.currentTimeMillis());
        status.put("version", "1.0.0");
        status.put("activeDetectors", 5);
        status.put("uptime", System.currentTimeMillis());

        return ResponseEntity.ok(status);
    }
}

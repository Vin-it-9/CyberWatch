package org.cyberwatch.controller;

import org.cyberwatch.service.SecurityMetricsService;
import org.cyberwatch.service.AlertService;
import org.cyberwatch.service.IPBlockingService;
import org.cyberwatch.model.SecurityMetrics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;

import java.util.HashMap;
import java.util.Map;

@Controller
public class SecurityWebSocketController {

    @Autowired
    private SecurityMetricsService metricsService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private IPBlockingService blockingService;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @MessageMapping("/dashboard/connect")
    @SendTo("/topic/dashboard-init")
    public Map<String, Object> handleDashboardConnection() {
        Map<String, Object> initialData = new HashMap<>();
        initialData.put("metrics", metricsService.getCurrentMetrics());
        initialData.put("recentAlerts", alertService.getRecentAlerts(5));
        initialData.put("blockingStats", blockingService.getBlockingStats());
        initialData.put("timestamp", System.currentTimeMillis());
        initialData.put("status", "connected");

        return initialData;
    }

    @MessageMapping("/metrics/request")
    @SendTo("/topic/metrics-update")
    public Map<String, Object> getMetricsUpdate() {
        Map<String, Object> update = new HashMap<>();
        update.put("metrics", metricsService.getCurrentMetrics());
        update.put("hourlyStats", metricsService.getHourlyAttackStats());
        update.put("severityStats", metricsService.getAttackSeverityStats());
        update.put("blockingStats", blockingService.getBlockingStats());
        update.put("timestamp", System.currentTimeMillis());

        return update;
    }

    @Scheduled(fixedRate = 10000)
    public void sendPeriodicDashboardUpdates() {
        try {
            Map<String, Object> dashboardUpdate = new HashMap<>();
            dashboardUpdate.put("metrics", metricsService.getCurrentMetrics());
            dashboardUpdate.put("blockingStats", blockingService.getBlockingStats());
            dashboardUpdate.put("timestamp", System.currentTimeMillis());
            dashboardUpdate.put("type", "periodic_update");

            messagingTemplate.convertAndSend("/topic/dashboard-updates", dashboardUpdate);
        } catch (Exception e) {
            System.err.println("Error sending periodic dashboard updates: " + e.getMessage());
        }
    }

    @Scheduled(fixedRate = 30000)
    public void sendAttackTrends() {
        try {
            Map<String, Object> trendData = new HashMap<>();
            trendData.put("hourlyStats", metricsService.getHourlyAttackStats());
            trendData.put("trends", metricsService.getAttackTrendData());
            trendData.put("severityDistribution", metricsService.getAttackSeverityStats());
            trendData.put("timestamp", System.currentTimeMillis());

            messagingTemplate.convertAndSend("/topic/attack-trends", trendData);
        } catch (Exception e) {
            System.err.println("Error sending attack trends: " + e.getMessage());
        }
    }

    @Scheduled(fixedRate = 60000)
    public void sendSystemStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "ACTIVE");
        status.put("uptime", System.currentTimeMillis());
        status.put("activeConnections", getActiveConnections());
        status.put("systemHealth", "HEALTHY");
        status.put("timestamp", System.currentTimeMillis());

        messagingTemplate.convertAndSend("/topic/system-status", status);
    }

    private int getActiveConnections() {
        return 1;
    }
}

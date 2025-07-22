package org.cyberwatch.controller;


import org.cyberwatch.model.SecurityMetrics;
import org.cyberwatch.service.AlertService;
import org.cyberwatch.service.SecurityMetricsService;
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
    private SimpMessagingTemplate messagingTemplate;

    @MessageMapping("/dashboard/subscribe")
    @SendTo("/topic/dashboard-data")
    public SecurityMetrics getDashboardData() {
        return metricsService.getCurrentMetrics();
    }

    @MessageMapping("/metrics/request")
    @SendTo("/topic/metrics-update")
    public Map<String, Object> getMetricsUpdate() {
        Map<String, Object> update = new HashMap<>();
        update.put("metrics", metricsService.getCurrentMetrics());
        update.put("hourlyStats", metricsService.getHourlyAttackStats());
        update.put("severityStats", metricsService.getAttackSeverityStats());
        update.put("timestamp", System.currentTimeMillis());

        return update;
    }

    @Scheduled(fixedRate = 30000)
    public void sendPeriodicUpdates() {
        try {
            SecurityMetrics metrics = metricsService.getCurrentMetrics();
            messagingTemplate.convertAndSend("/topic/metrics-periodic", metrics);

            Map<String, Object> trendData = new HashMap<>();
            trendData.put("trends", metricsService.getAttackTrendData());
            trendData.put("hourlyStats", metricsService.getHourlyAttackStats());

            messagingTemplate.convertAndSend("/topic/attack-trends", trendData);
        } catch (Exception e) {
            System.err.println("Error sending periodic updates: " + e.getMessage());
        }
    }

    @Scheduled(fixedRate = 60000)
    public void sendSystemStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "online");
        status.put("timestamp", System.currentTimeMillis());
        status.put("activeDetectors", 5);

        messagingTemplate.convertAndSend("/topic/system-status", status);
    }
}

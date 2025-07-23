package org.cyberwatch.controller;

import org.cyberwatch.service.SecurityMetricsService;
import org.cyberwatch.service.IPBlockingService;
import org.cyberwatch.service.AlertService;
import org.cyberwatch.model.AttackLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.util.Map;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    @Autowired
    private SecurityMetricsService metricsService;

    @Autowired
    private IPBlockingService blockingService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private SecurityMetricsService securityMetricsService;


    @GetMapping("")
    public String dashboard(Model model) {
        try {
            model.addAttribute("initialMetrics", metricsService.getCurrentMetrics());
            List<AttackLog> recentAlerts = alertService.getRecentAlerts(10);
            model.addAttribute("recentAlerts", recentAlerts != null ? recentAlerts : Collections.emptyList());
            model.addAttribute("blockingStats", blockingService.getBlockingStats());
            model.addAttribute("systemStatus", "ACTIVE");

        } catch (Exception e) {
            System.err.println("Error loading dashboard data: " + e.getMessage());
            model.addAttribute("recentAlerts", Collections.emptyList());
            model.addAttribute("systemStatus", "ERROR");
        }

        return "dashboard/index";
    }

    @GetMapping("/attacks")
    public String attacksPage(Model model) {
        try {
            List<AttackLog> recentAttacks = alertService.getRecentAlerts(50);
            model.addAttribute("recentAttacks", recentAttacks != null ? recentAttacks : Collections.emptyList());
            model.addAttribute("attackStats", metricsService.getAttackSeverityStats());

        } catch (Exception e) {
            System.err.println("Error loading attacks data: " + e.getMessage());
            model.addAttribute("recentAttacks", Collections.emptyList());
        }

        return "dashboard/attacks";
    }


    @GetMapping("/analytics")
    public String analyticsPage() {
        return "dashboard/analytics";
    }

    @GetMapping("/api/consolidated-data")
    @ResponseBody
    public Map<String, Object> getConsolidatedData() {
        Map<String, Object> data = new HashMap<>();

        try {
            data.put("metrics", securityMetricsService.getCurrentMetrics());
            data.put("hourlyStats", securityMetricsService.getHourlyAttackStats());
            data.put("severityStats", securityMetricsService.getAttackSeverityStats());
            data.put("recentAlerts", alertService.getRecentAlerts(10));
            data.put("blockingStats", blockingService.getBlockingStats());
            data.put("blockedIPs", blockingService.getCurrentlyBlockedIPs());

            Map<String, Object> systemStatus = new HashMap<>();
            systemStatus.put("status", "ACTIVE");
            systemStatus.put("uptime", System.currentTimeMillis());
            systemStatus.put("detectorsActive", 12);
            data.put("systemStatus", systemStatus);

        } catch (Exception e) {
            System.err.println("Error getting consolidated data: " + e.getMessage());
        }

        return data;
    }

    @GetMapping("/settings")
    public String settingsPage(Model model) {
        try {
            model.addAttribute("blockingStats", blockingService.getBlockingStats());
            model.addAttribute("blockedIPs", blockingService.getCurrentlyBlockedIPs());
            model.addAttribute("systemHealth", "HEALTHY");
            model.addAttribute("uptime", "99.8%");

        } catch (Exception e) {
            System.err.println("Error loading settings data: " + e.getMessage());
            model.addAttribute("systemHealth", "ERROR");
        }

        return "dashboard/settings";
    }

}

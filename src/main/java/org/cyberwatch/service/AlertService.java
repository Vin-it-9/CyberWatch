package org.cyberwatch.service;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;

@Service
public class AlertService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired(required = false)
    private SimpMessagingTemplate messagingTemplate;

    @EventListener
    public void handleSecurityAlert(AttackLog attackLog) {
        if (messagingTemplate != null && attackLog != null) {
            try {
                Map<String, Object> alertData = createAlertData(attackLog);

                messagingTemplate.convertAndSend("/topic/security-alerts", alertData);
                messagingTemplate.convertAndSend("/topic/live-feed", alertData);

                if (attackLog.getAttackType() != null) {
                    messagingTemplate.convertAndSend("/topic/attacks/" + attackLog.getAttackType().toLowerCase(), alertData);
                }

                if (attackLog.getSeverity() == AttackLog.Severity.CRITICAL ||
                        attackLog.getSeverity() == AttackLog.Severity.HIGH) {

                    Map<String, Object> priorityAlert = createPriorityAlert(attackLog);
                    messagingTemplate.convertAndSend("/topic/priority-alerts", priorityAlert);

                    System.out.println("🚨 HIGH PRIORITY ALERT BROADCASTED: " + attackLog.getAttackType() +
                            " from " + attackLog.getSourceIp());
                }
            } catch (Exception e) {
                System.err.println("Error broadcasting alert: " + e.getMessage());
            }
        }

        processAdditionalAlertActions(attackLog);
    }

    private Map<String, Object> createAlertData(AttackLog attackLog) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("id", attackLog.getId());
        alertData.put("attackType", attackLog.getAttackType() != null ? attackLog.getAttackType() : "Unknown");
        alertData.put("sourceIp", attackLog.getSourceIp() != null ? attackLog.getSourceIp() : "Unknown");
        alertData.put("description", attackLog.getDescription() != null ? attackLog.getDescription() : "No description");
        alertData.put("severity", attackLog.getSeverity() != null ? attackLog.getSeverity().toString() : "UNKNOWN");
        alertData.put("timestamp", attackLog.getDetectedAt() != null ?
                attackLog.getDetectedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) :
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        alertData.put("blocked", attackLog.isBlocked());
        alertData.put("targetEndpoint", attackLog.getTargetEndpoint() != null ? attackLog.getTargetEndpoint() : "Unknown");
        alertData.put("userAgent", attackLog.getUserAgent() != null ? attackLog.getUserAgent() : "Unknown");
        alertData.put("requestMethod", attackLog.getRequestMethod() != null ? attackLog.getRequestMethod() : "Unknown");
        alertData.put("severityColor", getSeverityColor(attackLog.getSeverity()));
        alertData.put("severityIcon", getSeverityIcon(attackLog.getSeverity()));

        return alertData;
    }

    private Map<String, Object> createPriorityAlert(AttackLog attackLog) {
        Map<String, Object> priorityAlert = new HashMap<>();
        priorityAlert.put("title", "🚨 HIGH PRIORITY SECURITY ALERT");
        priorityAlert.put("message", String.format("%s attack detected from %s",
                attackLog.getAttackType() != null ? attackLog.getAttackType() : "Unknown",
                attackLog.getSourceIp() != null ? attackLog.getSourceIp() : "Unknown"));
        priorityAlert.put("severity", attackLog.getSeverity() != null ? attackLog.getSeverity().toString() : "UNKNOWN");
        priorityAlert.put("timestamp", System.currentTimeMillis());
        priorityAlert.put("alert", createAlertData(attackLog));
        priorityAlert.put("requiresAction", true);

        return priorityAlert;
    }

    private String getSeverityColor(AttackLog.Severity severity) {
        if (severity == null) return "gray";
        return switch (severity) {
            case CRITICAL -> "red";
            case HIGH -> "orange";
            case MEDIUM -> "yellow";
            case LOW -> "blue";
        };
    }

    private String getSeverityIcon(AttackLog.Severity severity) {
        if (severity == null) return "⚪";
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🔵";
        };
    }

    public List<AttackLog> getRecentAlerts(int limit) {
        try {
            if (limit <= 0) limit = 50;
            List<AttackLog> attacks = attackLogRepository.findTop50ByOrderByDetectedAtDesc();
            return attacks != null ? attacks.stream().limit(limit).toList() : Collections.emptyList();
        } catch (Exception e) {
            System.err.println("Error getting recent alerts: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public List<AttackLog> getAlertsByType(String attackType) {
        try {
            return attackLogRepository.findByAttackTypeOrderByDetectedAtDesc(attackType);
        } catch (Exception e) {
            System.err.println("Error getting alerts by type: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public List<AttackLog> getAlertsByIP(String sourceIp) {
        try {
            return attackLogRepository.findBySourceIpOrderByDetectedAtDesc(sourceIp);
        } catch (Exception e) {
            System.err.println("Error getting alerts by IP: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public List<AttackLog> getAlertsInTimeRange(LocalDateTime start, LocalDateTime end) {
        try {
            return attackLogRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(start, end);
        } catch (Exception e) {
            System.err.println("Error getting alerts in time range: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    private void processAdditionalAlertActions(AttackLog attackLog) {
        if (attackLog != null &&
                (attackLog.getSeverity() == AttackLog.Severity.CRITICAL ||
                        attackLog.getSeverity() == AttackLog.Severity.HIGH)) {

            System.out.println("🚨 HIGH SEVERITY ALERT: " + attackLog.getAttackType() +
                    " from " + attackLog.getSourceIp());
        }
    }
}

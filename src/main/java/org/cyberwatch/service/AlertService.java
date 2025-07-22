package org.cyberwatch.service;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AlertService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired(required = false)
    private SimpMessagingTemplate messagingTemplate;

    @EventListener
    public void handleSecurityAlert(AttackLog attackLog) {

        if (messagingTemplate != null) {
            Map<String, Object> alertData = new HashMap<>();
            alertData.put("id", attackLog.getId());
            alertData.put("attackType", attackLog.getAttackType());
            alertData.put("sourceIp", attackLog.getSourceIp());
            alertData.put("description", attackLog.getDescription());
            alertData.put("severity", attackLog.getSeverity().toString());
            alertData.put("timestamp", attackLog.getDetectedAt().toString());
            alertData.put("blocked", attackLog.isBlocked());

            messagingTemplate.convertAndSend("/topic/security-alerts", alertData);
        }

        processHighSeverityAlert(attackLog);
    }

    public List<AttackLog> getRecentAlerts(int limit) {
        if (limit <= 0) limit = 50;
        return attackLogRepository.findTop50ByOrderByDetectedAtDesc()
                .stream()
                .limit(limit)
                .toList();
    }

    public List<AttackLog> getAlertsByType(String attackType) {
        return attackLogRepository.findByAttackTypeOrderByDetectedAtDesc(attackType);
    }

    public List<AttackLog> getAlertsByIP(String sourceIp) {
        return attackLogRepository.findBySourceIpOrderByDetectedAtDesc(sourceIp);
    }

    public List<AttackLog> getAlertsInTimeRange(LocalDateTime start, LocalDateTime end) {
        return attackLogRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(start, end);
    }

    private void processHighSeverityAlert(AttackLog attackLog) {
        if (attackLog.getSeverity() == AttackLog.Severity.CRITICAL ||
                attackLog.getSeverity() == AttackLog.Severity.HIGH) {

            System.out.println("ALERT: " + attackLog.getAttackType() +
                    " from " + attackLog.getSourceIp());
            System.out.println("Description: " + attackLog.getDescription());
            System.out.println("Detected at: " + attackLog.getDetectedAt());


            // In production, you would send email/SMS alerts here
            // emailService.sendCriticalAlert(attackLog);
            // smsService.sendAlert(attackLog);
        }
    }
}


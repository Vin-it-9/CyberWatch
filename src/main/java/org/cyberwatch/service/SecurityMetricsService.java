package org.cyberwatch.service;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.model.SecurityMetrics;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class SecurityMetricsService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    public SecurityMetrics getCurrentMetrics() {
        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);

        SecurityMetrics metrics = new SecurityMetrics();

        long totalAttacks = attackLogRepository.countAttacksSince(last24Hours);
        metrics.setTotalAttacks(totalAttacks);

        metrics.setBlockedAttacks(calculateBlockedAttacks(last24Hours));

        List<Object[]> attacksByType = attackLogRepository.getAttackCountsByType(last24Hours);
        Map<String, Long> attackTypeMap = new HashMap<>();
        for (Object[] row : attacksByType) {
            attackTypeMap.put((String) row[0], (Long) row[1]);
        }
        metrics.setAttacksByType(attackTypeMap);

        List<Object[]> topIPs = attackLogRepository.getTopSourceIps(last24Hours);
        Map<String, Long> topSourceIps = new HashMap<>();
        for (Object[] row : topIPs) {
            topSourceIps.put((String) row[0], (Long) row[1]);
        }
        metrics.setTopSourceIps(topSourceIps);

        return metrics;
    }

    public Map<String, Object> getHourlyAttackStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        LocalDateTime now = LocalDateTime.now();

        for (int i = 23; i >= 0; i--) {
            LocalDateTime hourStart = now.minusHours(i + 1);
            LocalDateTime hourEnd = now.minusHours(i);

            long count = attackLogRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(
                    hourStart, hourEnd).size();

            String hourLabel = String.format("%02d:00", hourStart.getHour());
            stats.put(hourLabel, count);
        }

        return stats;
    }

    public Map<String, Object> getAttackSeverityStats() {
        List<AttackLog> recentAttacks = attackLogRepository.findTop50ByOrderByDetectedAtDesc();

        Map<String, Long> severityCount = recentAttacks.stream()
                .collect(Collectors.groupingBy(
                        attack -> attack.getSeverity().toString(),
                        Collectors.counting()
                ));

        Map<String, Object> stats = new HashMap<>();
        stats.put("severityDistribution", severityCount);
        stats.put("totalRecent", recentAttacks.size());

        return stats;
    }

    public List<Map<String, Object>> getAttackTrendData() {
        LocalDateTime last7Days = LocalDateTime.now().minusDays(7);
        List<AttackLog> attacks = attackLogRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(
                last7Days, LocalDateTime.now());

        return attacks.stream()
                .map(attack -> {
                    Map<String, Object> data = new HashMap<>();
                    data.put("timestamp", attack.getDetectedAt().toString());
                    data.put("attackType", attack.getAttackType());
                    data.put("sourceIp", attack.getSourceIp());
                    data.put("severity", attack.getSeverity().toString());
                    return data;
                })
                .collect(Collectors.toList());
    }

    private long calculateBlockedAttacks(LocalDateTime since) {
        try {
            return attackLogRepository.countByBlockedTrueAndDetectedAtAfter(since);
        } catch (Exception e) {
            List<AttackLog> attacks = attackLogRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(
                    since, LocalDateTime.now());
            return attacks.stream().mapToLong(attack -> attack.isBlocked() ? 1 : 0).sum();
        }
    }
}

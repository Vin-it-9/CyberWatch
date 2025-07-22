package org.cyberwatch.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.cyberwatch.config.DetectionConfig;
import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class IPBlockingService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private DetectionConfig detectionConfig;

    // In-memory blocked IPs cache (expires after 1 hour)
    private final Cache<String, BlockedIP> blockedIPs = Caffeine.newBuilder()
            .expireAfterWrite(60, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    // Temporary suspicious IPs (expires after 15 minutes)
    private final Cache<String, AtomicInteger> suspiciousIPs = Caffeine.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .maximumSize(5000)
            .build();

    // User-Agent + IP combinations for sophisticated blocking
    private final Cache<String, BlockedAgent> blockedAgents = Caffeine.newBuilder()
            .expireAfterWrite(30, TimeUnit.MINUTES)
            .maximumSize(5000)
            .build();


    public boolean isIPBlocked(String ip) {

        if (!detectionConfig.isEnableRealBlocking()) {
            return false;
        }

        BlockedIP blocked = blockedIPs.getIfPresent(ip);
        return blocked != null && blocked.isActive();
    }


    public boolean isBlocked(String ip) {
        BlockedIP blocked = blockedIPs.getIfPresent(ip);
        return blocked != null && blocked.isActive();
    }


    public boolean isAgentBlocked(String ip, String userAgent) {

        if (!detectionConfig.isEnableRealBlocking()) {
            return false;
        }

        if (isIPBlocked(ip)) return true;

        String agentKey = ip + ":" + (userAgent != null ? userAgent.hashCode() : "unknown");
        BlockedAgent blocked = blockedAgents.getIfPresent(agentKey);
        return blocked != null && blocked.isActive();
    }


    public void blockIP(String ip, String reason, AttackLog.Severity severity, String userAgent) {
        int blockDurationMinutes = calculateBlockDuration(severity);

        BlockedIP blockedIP = new BlockedIP(
                ip,
                reason,
                severity,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(blockDurationMinutes),
                userAgent
        );

        blockedIPs.put(ip, blockedIP);

        if (userAgent != null) {
            String agentKey = ip + ":" + userAgent.hashCode();
            BlockedAgent blockedAgent = new BlockedAgent(ip, userAgent, reason, severity,
                    LocalDateTime.now().plusMinutes(blockDurationMinutes));
            blockedAgents.put(agentKey, blockedAgent);
        }

        if (detectionConfig.isEnableRealBlocking()) {
            System.out.println("🚫 BLOCKED IP (PRODUCTION): " + ip + " for " + blockDurationMinutes + " minutes. Reason: " + reason);
        } else {
            System.out.println("🧪 WOULD BLOCK IP (TESTING): " + ip + " for " + blockDurationMinutes + " minutes. Reason: " + reason);
        }

        System.out.println("🛡️ Block Level: " + severity + " | User-Agent: " +
                (userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "Unknown"));
    }


    public boolean markSuspicious(String ip, String userAgent, String attackType) {
        AtomicInteger suspicionCount = suspiciousIPs.get(ip, k -> new AtomicInteger(0));
        int count = suspicionCount.incrementAndGet();

        String mode = detectionConfig.isEnableRealBlocking() ? "PRODUCTION" : "TESTING";
        System.out.println("⚠️ SUSPICIOUS ACTIVITY (" + mode + "): IP " + ip + " marked suspicious " + count + " times for " + attackType);

        if (count >= 3) {
            blockIP(ip, "Multiple suspicious activities (" + count + "x) - " + attackType,
                    AttackLog.Severity.HIGH, userAgent);
            suspiciousIPs.invalidate(ip);
            return true;
        }

        return false;
    }


    private int calculateBlockDuration(AttackLog.Severity severity) {
        return switch (severity) {
            case CRITICAL -> 120;
            case HIGH -> 60;
            case MEDIUM -> 30;
            case LOW -> 15;
        };
    }


    public Map<String, Object> getBlockingStats() {
        Map<String, Object> stats = new ConcurrentHashMap<>();

        long activeBlocks = blockedIPs.asMap().values().stream()
                .mapToLong(blocked -> blocked.isActive() ? 1 : 0)
                .sum();

        long suspiciousCount = suspiciousIPs.estimatedSize();
        long blockedAgentsCount = blockedAgents.estimatedSize();

        stats.put("activeIPBlocks", activeBlocks);
        stats.put("suspiciousIPs", suspiciousCount);
        stats.put("blockedAgents", blockedAgentsCount);
        stats.put("totalBlockingRules", activeBlocks + blockedAgentsCount);
        stats.put("blockingMode", detectionConfig.isEnableRealBlocking() ? "PRODUCTION" : "TESTING");
        stats.put("realBlockingEnabled", detectionConfig.isEnableRealBlocking());

        return stats;
    }


    public Map<String, BlockedIP> getCurrentlyBlockedIPs() {
        Map<String, BlockedIP> activeBlocks = new ConcurrentHashMap<>();

        blockedIPs.asMap().forEach((ip, blocked) -> {
            if (blocked.isActive()) {
                activeBlocks.put(ip, blocked);
            }
        });

        return activeBlocks;
    }


    public boolean unblockIP(String ip) {
        BlockedIP blocked = blockedIPs.getIfPresent(ip);
        if (blocked != null) {
            blockedIPs.invalidate(ip);
            blockedAgents.asMap().entrySet().removeIf(entry -> entry.getValue().getIp().equals(ip));

            System.out.println("✅ UNBLOCKED IP: " + ip + " manually by admin");
            return true;
        }
        return false;
    }


    public void clearAllBlocks() {
        long blockedCount = blockedIPs.estimatedSize();
        long agentCount = blockedAgents.estimatedSize();
        long suspiciousCount = suspiciousIPs.estimatedSize();

        blockedIPs.invalidateAll();
        blockedAgents.invalidateAll();
        suspiciousIPs.invalidateAll();

        System.out.println("🧹 CLEARED ALL BLOCKS: " + blockedCount + " IPs, " +
                agentCount + " agents, " + suspiciousCount + " suspicious entries");
    }

    public Map<String, Object> getModeInfo() {
        Map<String, Object> info = new ConcurrentHashMap<>();
        boolean isProduction = detectionConfig.isEnableRealBlocking();

        info.put("mode", isProduction ? "PRODUCTION" : "TESTING");
        info.put("realBlockingEnabled", isProduction);
        info.put("description", isProduction ?
                "Real blocking is ENABLED - IPs will be actually blocked" :
                "Testing mode - Attacks detected and logged but no actual blocking");

        return info;
    }

    public static class BlockedIP {
        private final String ip;
        private final String reason;
        private final AttackLog.Severity severity;
        private final LocalDateTime blockedAt;
        private final LocalDateTime expiresAt;
        private final String userAgent;

        public BlockedIP(String ip, String reason, AttackLog.Severity severity,
                         LocalDateTime blockedAt, LocalDateTime expiresAt, String userAgent) {
            this.ip = ip;
            this.reason = reason;
            this.severity = severity;
            this.blockedAt = blockedAt;
            this.expiresAt = expiresAt;
            this.userAgent = userAgent;
        }

        public boolean isActive() {
            return LocalDateTime.now().isBefore(expiresAt);
        }

        // Getters
        public String getIp() { return ip; }
        public String getReason() { return reason; }
        public AttackLog.Severity getSeverity() { return severity; }
        public LocalDateTime getBlockedAt() { return blockedAt; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
        public String getUserAgent() { return userAgent; }
    }

    public static class BlockedAgent {
        private final String ip;
        private final String userAgent;
        private final String reason;
        private final AttackLog.Severity severity;
        private final LocalDateTime expiresAt;

        public BlockedAgent(String ip, String userAgent, String reason, AttackLog.Severity severity, LocalDateTime expiresAt) {
            this.ip = ip;
            this.userAgent = userAgent;
            this.reason = reason;
            this.severity = severity;
            this.expiresAt = expiresAt;
        }

        public boolean isActive() {
            return LocalDateTime.now().isBefore(expiresAt);
        }

        // Getters
        public String getIp() { return ip; }
        public String getUserAgent() { return userAgent; }
        public String getReason() { return reason; }
        public AttackLog.Severity getSeverity() { return severity; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
    }
}

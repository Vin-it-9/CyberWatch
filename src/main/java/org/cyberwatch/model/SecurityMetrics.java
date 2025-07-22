package org.cyberwatch.model;


import java.time.LocalDateTime;
import java.util.Map;

public class SecurityMetrics {
    private long totalAttacks;
    private long blockedAttacks;
    private Map<String, Long> attacksByType;
    private Map<String, Long> topSourceIps;
    private LocalDateTime lastUpdated;

    public SecurityMetrics() {
        this.lastUpdated = LocalDateTime.now();
    }
    public long getTotalAttacks() { return totalAttacks; }
    public void setTotalAttacks(long totalAttacks) { this.totalAttacks = totalAttacks; }

    public long getBlockedAttacks() { return blockedAttacks; }
    public void setBlockedAttacks(long blockedAttacks) { this.blockedAttacks = blockedAttacks; }

    public Map<String, Long> getAttacksByType() { return attacksByType; }
    public void setAttacksByType(Map<String, Long> attacksByType) { this.attacksByType = attacksByType; }

    public Map<String, Long> getTopSourceIps() { return topSourceIps; }
    public void setTopSourceIps(Map<String, Long> topSourceIps) { this.topSourceIps = topSourceIps; }

    public LocalDateTime getLastUpdated() { return lastUpdated; }
    public void setLastUpdated(LocalDateTime lastUpdated) { this.lastUpdated = lastUpdated; }
}

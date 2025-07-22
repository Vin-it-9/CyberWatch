package org.cyberwatch.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "attack_logs")
public class AttackLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "attack_type", nullable = false, length = 50)
    private String attackType;

    @Column(name = "source_ip", nullable = false, length = 45)
    private String sourceIp;

    @Column(name = "target_endpoint")
    private String targetEndpoint;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "request_method", length = 10)
    private String requestMethod;

    @Column(name = "request_payload", columnDefinition = "TEXT")
    private String requestPayload;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    @Column(name = "blocked")
    private boolean blocked = false;

    @Column(name = "attack_count")
    private int attackCount = 1;

    // Constructors
    public AttackLog() {
        this.detectedAt = LocalDateTime.now();
    }

    public AttackLog(String attackType, String sourceIp, String description) {
        this();
        this.attackType = attackType;
        this.sourceIp = sourceIp;
        this.description = description;
        this.severity = Severity.MEDIUM;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getTargetEndpoint() { return targetEndpoint; }
    public void setTargetEndpoint(String targetEndpoint) { this.targetEndpoint = targetEndpoint; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRequestMethod() { return requestMethod; }
    public void setRequestMethod(String requestMethod) { this.requestMethod = requestMethod; }

    public String getRequestPayload() { return requestPayload; }
    public void setRequestPayload(String requestPayload) { this.requestPayload = requestPayload; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }

    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }

    public int getAttackCount() { return attackCount; }
    public void setAttackCount(int attackCount) { this.attackCount = attackCount; }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
}


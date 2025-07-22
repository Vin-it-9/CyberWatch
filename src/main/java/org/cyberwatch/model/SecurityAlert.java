package org.cyberwatch.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_alerts")
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "attack_type", nullable = false)
    private String attackType;

    @Column(name = "source_ip", nullable = false)
    private String sourceIp;

    @Column(name = "description")
    private String description;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    @Column(name = "blocked")
    private boolean blocked = false;

    public SecurityAlert() {
        this.detectedAt = LocalDateTime.now();
    }

    public SecurityAlert(String attackType, String sourceIp, String description) {
        this();
        this.attackType = attackType;
        this.sourceIp = sourceIp;
        this.description = description;
        this.severity = Severity.MEDIUM;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
}

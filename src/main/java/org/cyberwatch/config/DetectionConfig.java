package org.cyberwatch.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "security.detection")
public class DetectionConfig {

    private int ddosThreshold = 100;
    private int bruteForceThreshold = 5;
    private int portScanThreshold = 20;
    private boolean enableEmailAlerts = false;
    private boolean enableSlackAlerts = false;
    private String alertEmail = "";
    private long cleanupInterval = 300000;

    // Getters and setters
    public int getDdosThreshold() {
        return ddosThreshold;
    }

    public void setDdosThreshold(int ddosThreshold) {
        this.ddosThreshold = ddosThreshold;
    }

    public int getBruteForceThreshold() {
        return bruteForceThreshold;
    }

    public void setBruteForceThreshold(int bruteForceThreshold) {
        this.bruteForceThreshold = bruteForceThreshold;
    }

    public int getPortScanThreshold() {
        return portScanThreshold;
    }

    public void setPortScanThreshold(int portScanThreshold) {
        this.portScanThreshold = portScanThreshold;
    }

    public boolean isEnableEmailAlerts() {
        return enableEmailAlerts;
    }

    public void setEnableEmailAlerts(boolean enableEmailAlerts) {
        this.enableEmailAlerts = enableEmailAlerts;
    }

    public boolean isEnableSlackAlerts() {
        return enableSlackAlerts;
    }

    public void setEnableSlackAlerts(boolean enableSlackAlerts) {
        this.enableSlackAlerts = enableSlackAlerts;
    }

    public String getAlertEmail() {
        return alertEmail;
    }

    public void setAlertEmail(String alertEmail) {
        this.alertEmail = alertEmail;
    }

    public long getCleanupInterval() {
        return cleanupInterval;
    }

    public void setCleanupInterval(long cleanupInterval) {
        this.cleanupInterval = cleanupInterval;
    }
}


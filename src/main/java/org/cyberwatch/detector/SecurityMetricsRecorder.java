package org.cyberwatch.detector;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class SecurityMetricsRecorder {

    private final Counter knownAttacksCounter;
    private final Counter unknownCounter;
    private final Counter suspiciousCounter;
    private final Counter errorCounter;
    private final Counter totalRequestsCounter;

    // Event streaming for real-time updates
    private final CopyOnWriteArrayList<String> recentEvents = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    // Statistics
    private final AtomicLong totalKnownAttacks = new AtomicLong(0);
    private final AtomicLong totalSuspicious = new AtomicLong(0);
    private final AtomicLong totalClean = new AtomicLong(0);
    private final AtomicLong totalErrors = new AtomicLong(0);

    @Autowired
    public SecurityMetricsRecorder(MeterRegistry registry) {
        // Initialize Micrometer counters
        this.knownAttacksCounter = Counter.builder("security.attacks.known")
                .description("Number of known attack patterns detected")
                .register(registry);

        this.unknownCounter = Counter.builder("security.requests.clean")
                .description("Number of clean requests processed")
                .register(registry);

        this.suspiciousCounter = Counter.builder("security.attacks.suspicious")
                .description("Number of suspicious patterns detected")
                .register(registry);

        this.errorCounter = Counter.builder("security.detection.errors")
                .description("Number of errors in attack detection")
                .register(registry);

        this.totalRequestsCounter = Counter.builder("security.requests.total")
                .description("Total number of security requests processed")
                .register(registry);

        // Start cleanup scheduler
        startEventCleanup();
    }

    public void incrementKnown() {
        knownAttacksCounter.increment();
        totalKnownAttacks.incrementAndGet();
        totalRequestsCounter.increment();

        String event = String.format("[%s] KNOWN_ATTACK - Total: %d",
                getCurrentTimestamp(), totalKnownAttacks.get());
        addEvent(event);

        System.out.println("📊 METRICS: Known attack detected. Total known attacks: " + totalKnownAttacks.get());
    }

    public void incrementUnknown() {
        unknownCounter.increment();
        totalClean.incrementAndGet();
        totalRequestsCounter.increment();

        String event = String.format("[%s] CLEAN_REQUEST - Total: %d",
                getCurrentTimestamp(), totalClean.get());
        addEvent(event);
    }

    public void incrementSuspicious() {
        suspiciousCounter.increment();
        totalSuspicious.incrementAndGet();
        totalRequestsCounter.increment();

        String event = String.format("[%s] SUSPICIOUS_ACTIVITY - Total: %d",
                getCurrentTimestamp(), totalSuspicious.get());
        addEvent(event);

        System.out.println("📊 METRICS: Suspicious activity detected. Total suspicious: " + totalSuspicious.get());
    }

    public void incrementClean() {
        unknownCounter.increment();
        totalClean.incrementAndGet();
        totalRequestsCounter.increment();

        String event = String.format("[%s] CLEAN_REQUEST - Total: %d",
                getCurrentTimestamp(), totalClean.get());
        addEvent(event);
    }

    public void incrementError() {
        errorCounter.increment();
        totalErrors.incrementAndGet();
        totalRequestsCounter.increment();

        String event = String.format("[%s] DETECTION_ERROR - Total: %d",
                getCurrentTimestamp(), totalErrors.get());
        addEvent(event);

        System.out.println("📊 METRICS: Detection error occurred. Total errors: " + totalErrors.get());
    }

    // Event streaming methods
    public java.util.List<String> getRecentEvents() {
        return new java.util.ArrayList<>(recentEvents);
    }

    public String getLatestEvent() {
        return recentEvents.isEmpty() ? "No events yet" : recentEvents.get(recentEvents.size() - 1);
    }

    // Statistics methods
    public long getTotalKnownAttacks() {
        return totalKnownAttacks.get();
    }

    public long getTotalSuspicious() {
        return totalSuspicious.get();
    }

    public long getTotalClean() {
        return totalClean.get();
    }

    public long getTotalErrors() {
        return totalErrors.get();
    }

    public long getTotalRequests() {
        return totalKnownAttacks.get() + totalSuspicious.get() + totalClean.get() + totalErrors.get();
    }

    public String getSecuritySummary() {
        return String.format(
                "🛡️ SECURITY SUMMARY:\n" +
                        "├── Known Attacks: %d\n" +
                        "├── Suspicious Activities: %d\n" +
                        "├── Clean Requests: %d\n" +
                        "├── Detection Errors: %d\n" +
                        "└── Total Processed: %d",
                getTotalKnownAttacks(),
                getTotalSuspicious(),
                getTotalClean(),
                getTotalErrors(),
                getTotalRequests()
        );
    }

    // Private helper methods
    private void addEvent(String event) {
        recentEvents.add(event);
        // Keep only last 100 events to prevent memory issues
        if (recentEvents.size() > 100) {
            recentEvents.remove(0);
        }
    }

    private String getCurrentTimestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    private void startEventCleanup() {
        // Clean old events every 5 minutes
        scheduler.scheduleAtFixedRate(() -> {
            if (recentEvents.size() > 50) {
                while (recentEvents.size() > 50) {
                    recentEvents.remove(0);
                }
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    // For compatibility with event streaming (simplified version)
    public java.util.stream.Stream<String> eventStream() {
        return recentEvents.stream();
    }
}

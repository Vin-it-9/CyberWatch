package org.cyberwatch.controller;

import org.cyberwatch.config.DetectionConfig;
import org.cyberwatch.repository.AttackLogRepository;
import org.cyberwatch.service.IPBlockingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*")
public class AdminApiController {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private DetectionConfig detectionConfig;

    @Autowired
    private IPBlockingService ipBlockingService;

    @PostMapping("/toggle-blocking")
    public ResponseEntity<Map<String, Object>> toggleBlocking(@RequestParam boolean enabled) {
        detectionConfig.setEnableRealBlocking(enabled);

        Map<String, Object> response = new HashMap<>();
        response.put("blockingEnabled", enabled);
        response.put("mode", enabled ? "PRODUCTION" : "TESTING");
        response.put("message", enabled ?
                "🔒 Real blocking ENABLED - IPs will be actually blocked" :
                "🧪 Testing mode ENABLED - Attacks detected but no actual blocking");
        response.put("timestamp", LocalDateTime.now());

        System.out.println("🔧 ADMIN: Blocking mode changed to " + (enabled ? "PRODUCTION" : "TESTING"));

        return ResponseEntity.ok(response);
    }

    @GetMapping("/blocking-status")
    public ResponseEntity<Map<String, Object>> getBlockingStatus() {
        return ResponseEntity.ok(ipBlockingService.getModeInfo());
    }

    @PostMapping("/clear-blocked-ips")
    public ResponseEntity<Map<String, Object>> clearBlockedIPs() {
        ipBlockingService.clearAllBlocks();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "All blocked IPs, agents, and suspicious entries cleared for testing");
        response.put("timestamp", LocalDateTime.now());
        response.put("mode", detectionConfig.isEnableRealBlocking() ? "PRODUCTION" : "TESTING");

        return ResponseEntity.ok(response);
    }

    @GetMapping("/system-info")
    public ResponseEntity<Map<String, Object>> getSystemInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("detectionMode", ipBlockingService.getModeInfo());
        info.put("blockingStats", ipBlockingService.getBlockingStats());
        info.put("blockedIPs", ipBlockingService.getCurrentlyBlockedIPs());
        info.put("configStatus", Map.of(
                "enableRealBlocking", detectionConfig.isEnableRealBlocking(),
                "ddosThreshold", detectionConfig.getDdosThreshold(),
                "bruteForceThreshold", detectionConfig.getBruteForceThreshold()
        ));

        return ResponseEntity.ok(info);
    }

    @PostMapping("/clear-logs")
    public ResponseEntity<Map<String, Object>> clearLogs() {
        long deletedCount = attackLogRepository.count();
        attackLogRepository.deleteAll();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Attack logs cleared successfully");
        response.put("deletedCount", deletedCount);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAdminStats() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("totalLogs", attackLogRepository.count());
        stats.put("databaseSize", "N/A");
        stats.put("oldestLog", attackLogRepository.findAll()
                .stream()
                .findFirst()
                .map(log -> log.getDetectedAt())
                .orElse(null));

        return ResponseEntity.ok(stats);
    }
}


package org.cyberwatch.controller;

import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*")
public class AdminApiController {

    @Autowired
    private AttackLogRepository attackLogRepository;

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


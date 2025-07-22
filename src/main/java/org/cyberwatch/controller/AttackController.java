package org.cyberwatch.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.cyberwatch.detector.SecurityMetricsRecorder;
import org.cyberwatch.service.AttackDetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/attack")
@Tag(name = "Attack Detection", description = "Traditional attack detection API")
public class AttackController {

    @Autowired
    private AttackDetectionService attackDetectionService;

    @Autowired
    private SecurityMetricsRecorder recorder;

    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(5);

    @GetMapping("/detect")
    @Operation(summary = "Detect attacks in payload")
    public String detect(@RequestParam String payload, HttpServletRequest request) {
        String clientIP = getClientIP(request);
        return attackDetectionService.detect(payload, clientIP);
    }

    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "Real-time attack detection stream")
    public SseEmitter stream() {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);

        executor.scheduleAtFixedRate(() -> {
            try {
                String event = recorder.getLatestEvent();
                emitter.send("Security Event: " + event);
            } catch (IOException e) {
                emitter.complete();
            }
        }, 0, 5, TimeUnit.SECONDS);

        return emitter;
    }

    @GetMapping("/metrics")
    @Operation(summary = "Get security metrics")
    public String getMetrics() {
        return recorder.getSecuritySummary();
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

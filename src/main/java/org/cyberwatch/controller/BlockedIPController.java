package org.cyberwatch.controller;


import org.cyberwatch.service.IPBlockingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
public class BlockedIPController {

    @Autowired
    private IPBlockingService ipBlockingService;

    @GetMapping("/access-denied")
    public String accessDenied(
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String reason,
            @RequestParam(required = false) String timestamp,
            Model model) {

        if (ip == null) {
            ip = "Unknown";
        }

        try {
            var blockedIPs = ipBlockingService.getCurrentlyBlockedIPs();
            var blockDetails = blockedIPs.get(ip);

            if (blockDetails != null) {
                model.addAttribute("blockReason", blockDetails.getReason());
                model.addAttribute("severity", blockDetails.getSeverity().toString());
                model.addAttribute("blockedAt", blockDetails.getBlockedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                model.addAttribute("expiresAt", blockDetails.getExpiresAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                model.addAttribute("userAgent", blockDetails.getUserAgent());
                long remainingMinutes = java.time.Duration.between(LocalDateTime.now(), blockDetails.getExpiresAt()).toMinutes();
                model.addAttribute("remainingTime", Math.max(0, remainingMinutes));
            } else {
                model.addAttribute("blockReason", reason != null ? reason : "Security violation detected");
                model.addAttribute("severity", "UNKNOWN");
                model.addAttribute("remainingTime", 0);
            }
        } catch (Exception e) {
            model.addAttribute("blockReason", reason != null ? reason : "IP address has been blocked due to security concerns");
            model.addAttribute("severity", "UNKNOWN");
            model.addAttribute("remainingTime", 0);
        }

        model.addAttribute("blockedIP", ip);
        model.addAttribute("currentTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        model.addAttribute("contactEmail", "security@cyberwatch.com");
        model.addAttribute("supportUrl", "/dashboard");

        return "error/access-denied";
    }
}

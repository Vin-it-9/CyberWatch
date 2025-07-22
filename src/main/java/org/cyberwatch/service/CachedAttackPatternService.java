package org.cyberwatch.service;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class CachedAttackPatternService {

    private final List<Pattern> attackPatterns = Arrays.asList(
            // --- SQL Injection (SQLi) ---
            // Matches common SQL keywords, union-based, and error-based attacks
            Pattern.compile("(?i)(union.*select|select.*from|drop.*table|update.*set|insert.*into|declare.*@|exec.*master)", Pattern.CASE_INSENSITIVE),
            // Matches boolean-based and tautology attacks
            Pattern.compile("(?i)('.*or|--|#|;\\s*--|'\\d'='\\d)", Pattern.CASE_INSENSITIVE),
            // Matches blind SQLi techniques using time delays
            Pattern.compile("(?i)(WAITFOR DELAY|SLEEP\\(|BENCHMARK\\()", Pattern.CASE_INSENSITIVE),

            // --- Cross-Site Scripting (XSS) ---
            // Matches common script tags and protocols
            Pattern.compile("(?i)(<script.*?>|</script>|javascript:|vbscript:|data:text/html)", Pattern.CASE_INSENSITIVE),
            // Matches HTML event handlers and other dangerous attributes
            Pattern.compile("(?i)(onload|onerror|onmouseover|onfocus|onclick|oninput|autofocus|srcdoc|formaction|style=.*url)", Pattern.CASE_INSENSITIVE),
            // Matches encoded angle brackets and other XSS vectors
            Pattern.compile("(&#x3C;script|%3Cscript|&lt;script)", Pattern.CASE_INSENSITIVE),

            // --- Path Traversal & File Inclusion (LFI/RFI) ---
            // Matches directory traversal attempts
            Pattern.compile("(\\.\\./|\\.\\\\|%2e%2e%2f|%2e%2e%5c)", Pattern.CASE_INSENSITIVE),
            // Matches file inclusion using wrappers and protocols
            Pattern.compile("(?i)(file://|php://|zip://|phar://|data:)", Pattern.CASE_INSENSITIVE),
            // Matches attempts to access sensitive system files
            Pattern.compile("(?i)(/etc/passwd|/proc/self/environ|win.ini)", Pattern.CASE_INSENSITIVE),

            // --- Command Injection (RCE) ---
            // Matches shell command separators and backticks for execution
            Pattern.compile("(&&|\\|\\||;|,|`|\\$(?=\\())", Pattern.CASE_INSENSITIVE),
            // Matches common commands used for reconnaissance or exploitation
            Pattern.compile("(?i)(cat|ls|dir|whoami|uname|ifconfig|ipconfig|wget|curl|netcat|ncat|nc)", Pattern.CASE_INSENSITIVE),

            // --- Server-Side Request Forgery (SSRF) ---
            // Matches common cloud metadata endpoints and local addresses
            Pattern.compile("(?i)(169\\.254\\.169\\.254|metadata\\.google|localhost|127\\.0\\.0\\.1)", Pattern.CASE_INSENSITIVE),

            // --- XML External Entity (XXE) ---
            // Matches keywords used to declare external entities in XML
            Pattern.compile("(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|PUBLIC)", Pattern.CASE_INSENSITIVE),

            // --- Log Forging / Injection ---
            // Matches newline characters which can be used to forge log entries
            Pattern.compile("(%0a|%0d|\\n|\\r)", Pattern.CASE_INSENSITIVE)
    );

    @Cacheable(value = "attackPatternCache", key = "#pattern")
    public boolean isKnownAttackPattern(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return false;
        }

        try {
            String decodedPattern = java.net.URLDecoder.decode(pattern, "UTF-8");

            // Check against all known attack patterns
            for (Pattern attackPattern : attackPatterns) {
                if (attackPattern.matcher(decodedPattern).find()) {
                    return true;
                }
            }

            // Additional heuristic checks
            return isHighRiskPattern(decodedPattern);

        } catch (Exception e) {
            // If decoding fails, check original pattern
            for (Pattern attackPattern : attackPatterns) {
                if (attackPattern.matcher(pattern).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isHighRiskPattern(String input) {
        String lowerInput = input.toLowerCase();

        // Check for multiple suspicious keywords
        int suspiciousCount = 0;
        String[] suspiciousKeywords = {
                // XSS (Cross-Site Scripting)
                "script", "javascript", "eval", "alert", "prompt", "confirm", "document.cookie",
                "onload", "onerror", "onmouseover", "onclick", "iframe", "svg", "img", "src",
                "href", "formaction", "innerHTML", "<", ">",

                // SQL Injection (SQLi)
                "union", "select", "drop", "delete", "insert", "update", "from", "where",
                "benchmark", "sleep", "information_schema", "xp_cmdshell", "sp_configure",
                "' or '", "--", "#", ";",

                // Command Injection & Remote Code Execution (RCE)
                "exec", "system", "cmd", "powershell", "bash", "sh", "wget", "curl", "netcat",
                "/bin/bash", "&&", "||", "|", "`", "$( ",

                // Path Traversal & File Inclusion
                "../", "..\\", "/etc/passwd", "win.ini", "include", "require", "php://",
                "file://", "data:",

                // Server-Side Request Forgery (SSRF)
                "localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal",

                // XML External Entity (XXE)
                "ENTITY", "SYSTEM", "PUBLIC", "DOCTYPE"
        };

        for (String keyword : suspiciousKeywords) {
            if (lowerInput.contains(keyword)) {
                suspiciousCount++;
            }
        }

        // If multiple suspicious keywords found, consider it high risk
        return suspiciousCount >= 2;
    }
}


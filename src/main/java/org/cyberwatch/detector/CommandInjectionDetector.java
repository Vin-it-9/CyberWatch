package org.cyberwatch.detector;


import org.cyberwatch.service.BaseDetectionService;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class CommandInjectionDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> commandPatterns = Arrays.asList(
            // Unix/Linux command injection patterns
            Pattern.compile("(?i)(;\\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|wget|curl))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(\\|\\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|wget|curl))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(&&\\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|wget|curl))", Pattern.CASE_INSENSITIVE),

            // Windows command injection patterns
            Pattern.compile("(?i)(;\\s*(dir|type|net|ipconfig|systeminfo|tasklist))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(&\\s*(dir|type|net|ipconfig|systeminfo|tasklist))", Pattern.CASE_INSENSITIVE),

            // Command execution patterns
            Pattern.compile("(?i)`[^`]*`", Pattern.CASE_INSENSITIVE), // Backticks
            Pattern.compile("(?i)\\$\\([^)]*\\)", Pattern.CASE_INSENSITIVE), // $(command)
            Pattern.compile("(?i)(\\|\\|)", Pattern.CASE_INSENSITIVE), // OR operator

            // Remote code execution
            Pattern.compile("(?i)(wget|curl).*http", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(python|perl|php|ruby)\\s", Pattern.CASE_INSENSITIVE),

            // System file access
            Pattern.compile("(?i)(/etc/passwd|/etc/shadow|/proc/|/sys/)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(c:\\\\windows|c:\\\\boot\\.ini)", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {

        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            String[] values = parameters.get(paramName);
            for (String value : values) {
                if (containsCommandInjection(value)) {
                    logAttack("COMMAND_INJECTION", clientIP,
                            String.format("Command injection in parameter '%s': %s", paramName, value),
                            request);
                    return true;
                }
            }
        }

        String queryString = request.getQueryString();
        if (queryString != null && containsCommandInjection(queryString)) {
            logAttack("COMMAND_INJECTION", clientIP,
                    "Command injection in query string: " + queryString, request);
            return true;
        }

        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && containsCommandInjection(userAgent)) {
            logAttack("COMMAND_INJECTION", clientIP,
                    "Command injection in User-Agent: " + userAgent, request);
            return true;
        }

        return false;
    }

    private boolean containsCommandInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            for (Pattern pattern : commandPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            for (Pattern pattern : commandPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "COMMAND_INJECTION";
    }
}

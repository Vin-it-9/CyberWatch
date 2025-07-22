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
public class LogInjectionDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> logInjectionPatterns = Arrays.asList(
            // Newline characters for log injection
            Pattern.compile("\\n", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\r", Pattern.CASE_INSENSITIVE),
            Pattern.compile("%0a", Pattern.CASE_INSENSITIVE),
            Pattern.compile("%0d", Pattern.CASE_INSENSITIVE),

            // Null byte injection
            Pattern.compile("\\x00", Pattern.CASE_INSENSITIVE),
            Pattern.compile("%00", Pattern.CASE_INSENSITIVE),

            // Log format manipulation
            Pattern.compile("(?i)\\[(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\\]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}", Pattern.CASE_INSENSITIVE),

            // Common log injection attempts
            Pattern.compile("(?i)admin\\s+(logged|login|authenticated)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(root|administrator)\\s+access", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)system\\s+(compromised|hacked)", Pattern.CASE_INSENSITIVE),

            // ANSI escape sequences (for terminal manipulation)
            Pattern.compile("\\x1b\\[[0-9;]*[a-zA-Z]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\\\033\\[[0-9;]*[a-zA-Z]", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {

        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            String[] values = parameters.get(paramName);
            for (String value : values) {
                if (containsLogInjection(value)) {
                    logAttack("LOG_INJECTION", clientIP,
                            String.format("Log injection in parameter '%s': %s", paramName, sanitizeForLog(value)),
                            request);
                    return true;
                }
            }
        }

        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && containsLogInjection(userAgent)) {
            logAttack("LOG_INJECTION", clientIP,
                    "Log injection in User-Agent: " + sanitizeForLog(userAgent), request);
            return true;
        }

        String referer = request.getHeader("Referer");
        if (referer != null && containsLogInjection(referer)) {
            logAttack("LOG_INJECTION", clientIP,
                    "Log injection in Referer: " + sanitizeForLog(referer), request);
            return true;
        }

        return false;
    }

    private boolean containsLogInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            for (Pattern pattern : logInjectionPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            for (Pattern pattern : logInjectionPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    private String sanitizeForLog(String input) {
        return input.replaceAll("[\\r\\n\\x00-\\x1F\\x7F]", "_");
    }

    @Override
    public String getAttackType() {
        return "LOG_INJECTION";
    }
}

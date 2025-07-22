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
public class SQLInjectionDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> sqlPatterns = Arrays.asList(
            Pattern.compile("(?i)(union.*select)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(select.*from)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(drop.*table)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(insert.*into)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(delete.*from)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(update.*set)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*or.*'", Pattern.CASE_INSENSITIVE),
            Pattern.compile("--", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/\\*.*\\*/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(exec.*xp_)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(sp_.*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(1=1)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(1' or '1'='1)", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        // Check URL parameters
        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            String[] values = parameters.get(paramName);
            for (String value : values) {
                if (containsSQLPattern(value)) {
                    logAttack("SQL_INJECTION", clientIP,
                            String.format("SQL injection in parameter '%s': %s", paramName, value),
                            request);
                    return true;
                }
            }
        }

        // Check query string
        String queryString = request.getQueryString();
        if (queryString != null && containsSQLPattern(queryString)) {
            logAttack("SQL_INJECTION", clientIP,
                    "SQL injection in query string: " + queryString, request);
            return true;
        }

        // Check request URI
        String uri = request.getRequestURI();
        if (containsSQLPattern(uri)) {
            logAttack("SQL_INJECTION", clientIP,
                    "SQL injection in URI: " + uri, request);
            return true;
        }

        return false;
    }

    private boolean containsSQLPattern(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            // URL decode the input
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            // Check against all SQL injection patterns
            for (Pattern pattern : sqlPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            // If decoding fails, check original input
            for (Pattern pattern : sqlPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "SQL_INJECTION";
    }
}

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
public class XSSDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> xssPatterns = Arrays.asList(
            Pattern.compile("(?i)<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<script.*?>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)vbscript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)onload.*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)onerror.*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)onclick.*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)onmouseover.*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<iframe.*?>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<object.*?>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<embed.*?>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)alert\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)document\\.cookie", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        // Check URL parameters
        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            String[] values = parameters.get(paramName);
            for (String value : values) {
                if (containsXSSPattern(value)) {
                    logAttack("XSS", clientIP,
                            String.format("XSS attempt in parameter '%s': %s", paramName, value),
                            request);
                    return true;
                }
            }
        }

        // Check query string
        String queryString = request.getQueryString();
        if (queryString != null && containsXSSPattern(queryString)) {
            logAttack("XSS", clientIP,
                    "XSS attempt in query string: " + queryString, request);
            return true;
        }

        // Check headers (sometimes XSS can be in headers)
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && containsXSSPattern(userAgent)) {
            logAttack("XSS", clientIP,
                    "XSS attempt in User-Agent: " + userAgent, request);
            return true;
        }

        return false;
    }

    private boolean containsXSSPattern(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            // URL decode the input
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            // Check against all XSS patterns
            for (Pattern pattern : xssPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            // If decoding fails, check original input
            for (Pattern pattern : xssPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "XSS";
    }
}

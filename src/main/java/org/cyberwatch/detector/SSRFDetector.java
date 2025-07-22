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
public class SSRFDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> ssrfPatterns = Arrays.asList(
            // AWS metadata service
            Pattern.compile("(?i)169\\.254\\.169\\.254", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)metadata\\.amazonaws\\.com", Pattern.CASE_INSENSITIVE),

            // Local network addresses
            Pattern.compile("(?i)(localhost|127\\.0\\.0\\.1)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)192\\.168\\.[0-9]+\\.[0-9]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)10\\.[0-9]+\\.[0-9]+\\.[0-9]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]+\\.[0-9]+", Pattern.CASE_INSENSITIVE),

            // File protocol
            Pattern.compile("(?i)file://", Pattern.CASE_INSENSITIVE),

            // Gopher protocol for advanced SSRF
            Pattern.compile("(?i)gopher://", Pattern.CASE_INSENSITIVE),

            // Internal service discovery
            Pattern.compile("(?i)(consul|etcd|kubernetes)", Pattern.CASE_INSENSITIVE),

            // Common internal ports
            Pattern.compile("(?i):(22|23|25|53|110|143|993|995|1433|3306|5432|6379|8080|9200|27017)", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {

        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            String[] values = parameters.get(paramName);
            for (String value : values) {
                if (containsSSRF(value)) {
                    logAttack("SSRF", clientIP,
                            String.format("SSRF attempt in parameter '%s': %s", paramName, value),
                            request);
                    return true;
                }
            }
        }

        return false;
    }

    private boolean containsSSRF(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            for (Pattern pattern : ssrfPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            for (Pattern pattern : ssrfPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "SSRF";
    }
}

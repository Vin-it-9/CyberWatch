package org.cyberwatch.detector;

import org.cyberwatch.service.BaseDetectionService;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class XXEDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> xxePatterns = Arrays.asList(
            // External entity declarations
            Pattern.compile("(?i)<!ENTITY.*SYSTEM", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<!ENTITY.*PUBLIC", Pattern.CASE_INSENSITIVE),

            // File system access
            Pattern.compile("(?i)file://", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)SYSTEM\\s+[\"'][^\"']*(/etc/passwd|/etc/shadow)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)SYSTEM\\s+[\"'][^\"']*(c:\\\\boot\\.ini|c:\\\\windows)", Pattern.CASE_INSENSITIVE),

            // HTTP-based XXE
            Pattern.compile("(?i)SYSTEM\\s+[\"']https?://", Pattern.CASE_INSENSITIVE),

            // FTP-based XXE
            Pattern.compile("(?i)SYSTEM\\s+[\"']ftp://", Pattern.CASE_INSENSITIVE),

            // Parameter entity
            Pattern.compile("(?i)<!ENTITY\\s+%", Pattern.CASE_INSENSITIVE),

            // XXE payloads
            Pattern.compile("(?i)&[a-zA-Z0-9_]+;.*ENTITY", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {

        String contentType = request.getContentType();
        if (contentType != null &&
                (contentType.contains("xml") || contentType.contains("application/xml") ||
                        contentType.contains("text/xml"))) {

            try {
                String body = getRequestBody(request);
                if (body != null && containsXXE(body)) {
                    logAttack("XXE", clientIP,
                            "XXE injection attempt detected in XML payload", request);
                    return true;
                }
            } catch (IOException e) {
                System.err.println("Error reading request body for XXE detection: " + e.getMessage());
            }
        }

        String queryString = request.getQueryString();
        if (queryString != null && containsXXE(queryString)) {
            logAttack("XXE", clientIP,
                    "XXE attempt in query parameters: " + queryString, request);
            return true;
        }

        return false;
    }

    private boolean containsXXE(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        for (Pattern pattern : xxePatterns) {
            if (pattern.matcher(input).find()) {
                return true;
            }
        }

        return false;
    }

    private String getRequestBody(HttpServletRequest request) throws IOException {
        BufferedReader reader = request.getReader();
        StringBuilder body = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            body.append(line);
        }

        return body.toString();
    }

    @Override
    public String getAttackType() {
        return "XXE";
    }
}

package org.cyberwatch.detector;

import org.cyberwatch.service.BaseDetectionService;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class FileUploadAttackDetector extends BaseDetectionService implements AttackDetector {

    private final List<String> dangerousExtensions = Arrays.asList(
            ".php", ".jsp", ".asp", ".aspx", ".exe", ".bat", ".cmd", ".sh", ".pl", ".py",
            ".rb", ".java", ".class", ".jar", ".war", ".ear", ".scr", ".vbs", ".js", ".htaccess"
    );

    private final List<Pattern> executableSignatures = Arrays.asList(
            Pattern.compile("^MZ", Pattern.CASE_INSENSITIVE), // Windows PE
            Pattern.compile("^\\x7fELF", Pattern.CASE_INSENSITIVE), // Linux ELF
            Pattern.compile("^\\xca\\xfe\\xba\\xbe", Pattern.CASE_INSENSITIVE), // Java class
            Pattern.compile("^PK\\x03\\x04.*\\.class", Pattern.CASE_INSENSITIVE), // JAR file
            Pattern.compile("^\\x50\\x4b\\x03\\x04", Pattern.CASE_INSENSITIVE) // ZIP/JAR
    );

    private final List<Pattern> webShellPatterns = Arrays.asList(
            Pattern.compile("(?i)<\\?php.*system\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<\\?php.*exec\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<\\?php.*shell_exec\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<\\?php.*passthru\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<%.*Runtime\\.getRuntime\\(\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)<%.*ProcessBuilder", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {
        String contentType = request.getContentType();

        if (contentType != null && contentType.toLowerCase().contains("multipart/form-data")) {

            Map<String, String[]> parameters = request.getParameterMap();
            for (String paramName : parameters.keySet()) {
                String[] values = parameters.get(paramName);
                for (String value : values) {
                    if (isDangerousFileUpload(value, paramName)) {
                        logAttack("FILE_UPLOAD_ATTACK", clientIP,
                                String.format("Malicious file upload attempt in parameter '%s': %s", paramName, value),
                                request);
                        return true;
                    }
                }
            }
        }

        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            if (paramName.toLowerCase().contains("file") ||
                    paramName.toLowerCase().contains("upload") ||
                    paramName.toLowerCase().contains("attachment")) {

                String[] values = parameters.get(paramName);
                for (String value : values) {
                    if (isDangerousFileContent(value)) {
                        logAttack("FILE_UPLOAD_ATTACK", clientIP,
                                String.format("Dangerous file content in parameter '%s'", paramName),
                                request);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean isDangerousFileUpload(String value, String paramName) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String lowerValue = value.toLowerCase();
        for (String extension : dangerousExtensions) {
            if (lowerValue.endsWith(extension) || lowerValue.contains(extension)) {
                return true;
            }
        }

        if (lowerValue.matches(".*\\.(jpg|jpeg|png|gif|pdf)\\.php.*") ||
                lowerValue.matches(".*\\.(txt|doc|docx)\\.jsp.*")) {
            return true;
        }

        if (lowerValue.contains("%00") || lowerValue.contains("\\x00")) {
            return true;
        }

        return false;
    }

    private boolean isDangerousFileContent(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }

        for (Pattern pattern : executableSignatures) {
            if (pattern.matcher(content).find()) {
                return true;
            }
        }

        for (Pattern pattern : webShellPatterns) {
            if (pattern.matcher(content).find()) {
                return true;
            }
        }

        if (content.toLowerCase().contains("<?php") &&
                (content.toLowerCase().contains("system(") ||
                        content.toLowerCase().contains("exec(") ||
                        content.toLowerCase().contains("shell_exec("))) {
            return true;
        }

        return false;
    }

    @Override
    public String getAttackType() {
        return "FILE_UPLOAD_ATTACK";
    }
}

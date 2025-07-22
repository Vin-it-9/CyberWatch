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
public class LDAPInjectionDetector extends BaseDetectionService implements AttackDetector {

    private final List<Pattern> ldapPatterns = Arrays.asList(
            // LDAP filter injection patterns
            Pattern.compile("(?i)\\*\\)\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\*\\)\\(&", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\*\\)\\(\\|", Pattern.CASE_INSENSITIVE),

            // LDAP blind injection
            Pattern.compile("(?i)\\)\\(\\|\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\)\\(&\\(", Pattern.CASE_INSENSITIVE),

            // Authentication bypass patterns
            Pattern.compile("(?i)\\*\\)\\(cn=\\*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\*\\)\\(uid=\\*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\*\\)\\(objectClass=\\*", Pattern.CASE_INSENSITIVE),

            // LDAP search filter manipulation
            Pattern.compile("(?i)\\)\\(\\|\\(password=\\*\\)\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)admin\\)\\(\\|\\(", Pattern.CASE_INSENSITIVE),

            // Common LDAP attributes in injection attempts
            Pattern.compile("(?i)\\)\\(\\|\\(cn=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\)\\(\\|\\(uid=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\)\\(\\|\\(sAMAccountName=", Pattern.CASE_INSENSITIVE),

            // LDAP special characters used for injection
            Pattern.compile("(?i)[()&|!>=<~].*[()&|!>=<~]", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public boolean detectAttack(HttpServletRequest request, String clientIP) {

        Map<String, String[]> parameters = request.getParameterMap();
        for (String paramName : parameters.keySet()) {
            if (isAuthenticationParameter(paramName)) {
                String[] values = parameters.get(paramName);
                for (String value : values) {
                    if (containsLDAPInjection(value)) {
                        logAttack("LDAP_INJECTION", clientIP,
                                String.format("LDAP injection in parameter '%s': %s", paramName, value),
                                request);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean isAuthenticationParameter(String paramName) {
        String lowerParamName = paramName.toLowerCase();
        return lowerParamName.contains("user") ||
                lowerParamName.contains("login") ||
                lowerParamName.contains("auth") ||
                lowerParamName.contains("name") ||
                lowerParamName.contains("id") ||
                lowerParamName.contains("account") ||
                lowerParamName.contains("cn") ||
                lowerParamName.contains("uid") ||
                lowerParamName.contains("dn");
    }

    private boolean containsLDAPInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        try {
            String decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);

            for (Pattern pattern : ldapPatterns) {
                if (pattern.matcher(decodedInput).find()) {
                    return true;
                }
            }

            return hasLDAPInjectionCharacteristics(decodedInput);

        } catch (Exception e) {
            for (Pattern pattern : ldapPatterns) {
                if (pattern.matcher(input).find()) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean hasLDAPInjectionCharacteristics(String input) {

        int specialCharCount = 0;
        char[] specialChars = {'(', ')', '&', '|', '!', '=', '>', '<', '~', '*'};

        for (char c : input.toCharArray()) {
            for (char special : specialChars) {
                if (c == special) {
                    specialCharCount++;
                    break;
                }
            }
        }

        if (specialCharCount >= 3) {
            return true;
        }

        long openParens = input.chars().filter(ch -> ch == '(').count();
        long closeParens = input.chars().filter(ch -> ch == ')').count();

        return Math.abs(openParens - closeParens) > 0;
    }

    @Override
    public String getAttackType() {
        return "LDAP_INJECTION";
    }
}

package org.cyberwatch.detector;

import jakarta.servlet.http.HttpServletRequest;

public interface AttackDetector {

    boolean detectAttack(HttpServletRequest request, String clientIP);

    String getAttackType();

    default double getConfidenceLevel() {
        return 0.8;
    }

    default boolean isEnabled() {
        return true;
    }
}

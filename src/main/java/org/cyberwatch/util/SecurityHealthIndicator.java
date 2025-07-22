package org.cyberwatch.util;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class SecurityHealthIndicator implements HealthIndicator {

    @Override
    public Health health() {
        boolean ok = true;
        return ok ? Health.up()
                .withDetail("security","active")
                .build()
                : Health.down()
                .withDetail("security","issue detected")
                .build();
    }
}

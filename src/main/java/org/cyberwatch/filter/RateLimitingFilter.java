package org.cyberwatch.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Order(0)
public class RateLimitingFilter implements Filter {

    private final Cache<String, AtomicInteger> rateLimitCache;
    private static final int RATE_LIMIT = 100;

    public RateLimitingFilter() {
        this.rateLimitCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .maximumSize(10000)
                .build();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String clientIP = getClientIP(httpRequest);
        AtomicInteger requestCount = rateLimitCache.get(clientIP, k -> new AtomicInteger(0));
        int currentCount = requestCount.incrementAndGet();

        if (currentCount > RATE_LIMIT) {
            httpResponse.setStatus(HttpServletResponse.SC_CONTINUE);
            httpResponse.getWriter().write("Rate limit exceeded");
            return;
        }

        chain.doFilter(request, response);
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

package ucr.ac.cr.medivault.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    static final int LOGIN_LIMIT_PER_MINUTE = 5;
    static final int API_LIMIT_PER_MINUTE = 30;
    private static final int MAX_TRACKED_IPS = 10_000;

    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String ip = ClientIpResolver.resolve(request);
        Bucket bucket = null;

        if (path.startsWith("/api/v1/auth/login")) {
            bucket = obtener(loginBuckets, ip, LOGIN_LIMIT_PER_MINUTE);
        } else if (path.startsWith("/api/v1/expedientes")) {
            bucket = obtener(apiBuckets, ip, API_LIMIT_PER_MINUTE);
        }

        if (bucket == null) {
            filterChain.doFilter(request, response);
            return;
        }

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            filterChain.doFilter(request, response);
            return;
        }

        long retryAfter = Math.max(1, (long) Math.ceil(probe.getNanosToWaitForRefill() / 1_000_000_000.0));
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        ProblemJsonWriter.write(response, 429,
                "https://medivault.ucr.ac.cr/rate-limit",
                "Demasiadas Peticiones",
                "Limite superado. Espere " + retryAfter + "s.",
                path);
    }

    private Bucket obtener(Map<String, Bucket> buckets, String ip, int limit) {
        if (buckets.size() > MAX_TRACKED_IPS) {
            buckets.values().removeIf(b -> b.getAvailableTokens() >= limit);
        }
        return buckets.computeIfAbsent(ip, k -> nuevoBucket(limit));
    }

    private Bucket nuevoBucket(int limit) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(limit, Refill.intervally(limit, Duration.ofMinutes(1))))
                .build();
    }
}

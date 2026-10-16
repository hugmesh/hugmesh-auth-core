package net.hugmesh.authcore.config;

import net.hugmesh.authcore.account.AccountStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * The HTTP-resolved counterpart of {@link BffCookieAuthenticationWebFilter}, for services that do
 * NOT own the accounts/bff_session tables (user-bff, mod-bff, federation-api): the opaque
 * {@code bff_} session (carried in {@code Authorization} by {@link SessionCookieWebFilter}) is
 * resolved through a {@link BffSessionIntrospector} and turned into a real Spring Security
 * {@link Authentication}, with the SAME authority mapping as the local-store filter.
 *
 * <h3>Wiring</h3>
 * Deliberately NOT a {@code @Component}: a consumer that scans this package would otherwise get
 * it, unconfigured, next to the local-store filter. A consumer declares it as a {@code @Bean}
 * built from its own introspector, e.g.
 * {@code new BffSessionIntrospectionWebFilter(new HttpBffSessionIntrospector(webClient), Duration.ofSeconds(2))}.
 * It runs at {@code HIGHEST_PRECEDENCE + 10}, like {@link BffCookieAuthenticationWebFilter}; a
 * service should register one or the other, not both.
 *
 * <h3>Outcomes</h3>
 * <ul>
 *   <li>No {@code Authorization: Bearer bff_...} header: pass through, the introspector is not
 *       called (a Casdoor JWT request is untouched).</li>
 *   <li>Unknown or expired session (introspector completes empty): pass through
 *       unauthenticated, so the service's own rules produce the 401.</li>
 *   <li>Account {@code suspended} or {@code banned}: {@code 403} with
 *       {@code X-Bff-Denied: account-<status>}; the chain is not invoked.</li>
 *   <li>Status missing, blank or any value other than {@code active}/{@code suspended}/{@code banned}:
 *       {@code 403} with {@code X-Bff-Denied: account-status-unrecognized} (allow-list: only an
 *       explicit {@code active} is granted); the chain is not invoked.</li>
 *   <li>Introspector error or timeout: {@code 503} with {@code {"error":"session_backend_unavailable"}};
 *       the chain is not invoked (fail closed, never an anonymous or floor grant).</li>
 *   <li>Status {@code active}: the chain runs once with the mapped authentication in its security context.</li>
 * </ul>
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BffSessionIntrospectionWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(BffSessionIntrospectionWebFilter.class);

    /** Response header naming why a session was refused. */
    public static final String DENIED_HEADER = "X-Bff-Denied";

    private static final String BFF_PREFIX = "bff_";

    private final BffSessionIntrospector introspector;
    private final Duration timeout;

    public BffSessionIntrospectionWebFilter(BffSessionIntrospector introspector, Duration timeout) {
        this.introspector = introspector;
        this.timeout = timeout;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null) {
            return chain.filter(exchange);
        }

        // Resolve to ONE decision first, then take exactly one terminal action: chain.filter()
        // is a Mono<Void> that never emits onNext, so flatMap + switchIfEmpty would run the
        // chain twice on success.
        return introspector.introspect(token)
                .timeout(timeout)
                .map(BffSessionIntrospectionWebFilter::decide)
                .defaultIfEmpty(Decision.PASS_THROUGH)
                .onErrorResume(ex -> {
                    log.error("[bff-session-introspection] introspection failed for a bff_ token, "
                            + "failing closed (503): {}", ex.toString());
                    return Mono.just(Decision.UNAVAILABLE);
                })
                .flatMap(d -> apply(d, exchange, chain));
    }

    private record Decision(Authentication authentication, String deniedReason, boolean unavailable) {
        static final Decision PASS_THROUGH = new Decision(null, null, false);
        static final Decision UNAVAILABLE = new Decision(null, null, true);
    }

    private static Decision decide(BffSessionIntrospection intro) {
        String status = intro.status();
        // ALLOW-LIST: authorities are granted ONLY for an explicit "active". A missing, blank,
        // padded or unrecognized status is refused with a constant reason (never the raw,
        // backend-supplied text); suspended/banned keep their specific reason.
        // Comparison is ASCII-only: String.equalsIgnoreCase folds U+0130 (dotted capital I) to
        // 'i' and U+017F (long s) to 's', so it would accept a non-ASCII lookalike of "active"
        // and echo a lookalike of "suspended" into the denial header.
        if (!asciiEqualsIgnoreCase(status, AccountStatus.ACTIVE)) {
            boolean banned = asciiEqualsIgnoreCase(status, AccountStatus.BANNED);
            if (banned || asciiEqualsIgnoreCase(status, AccountStatus.SUSPENDED)) {
                String lower = banned ? AccountStatus.BANNED : AccountStatus.SUSPENDED;
                log.warn("[bff-session-introspection] denied, account status={} id={}", lower, intro.id());
                return new Decision(null, "account-" + lower, false);
            }
            log.warn("[bff-session-introspection] denied, unrecognized account status (blank={}) id={}",
                    status == null || status.isBlank(), intro.id());
            return new Decision(null, "account-status-unrecognized", false);
        }
        return new Decision(new UsernamePasswordAuthenticationToken(intro.id(), null,
                BffCookieAuthenticationWebFilter.buildAuthorities(
                        intro.registrationComplete(), intro.roles(), intro.mfaSatisfied())), null, false);
    }

    /** True when {@code value} equals {@code expected} (lower-case ASCII) ignoring ASCII case
     *  only. */
    static boolean asciiEqualsIgnoreCase(String value, String expected) {
        if (value == null || value.length() != expected.length()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            }
            if (c != expected.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static Mono<Void> apply(Decision d, ServerWebExchange exchange, WebFilterChain chain) {
        if (d.authentication() != null) {
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(d.authentication()));
        }
        if (d.deniedReason() != null) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            exchange.getResponse().getHeaders().add(DENIED_HEADER, d.deniedReason());
            return exchange.getResponse().setComplete();
        }
        if (d.unavailable()) {
            exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            byte[] body = "{\"error\":\"session_backend_unavailable\"}".getBytes(StandardCharsets.UTF_8);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
        }
        return chain.filter(exchange);
    }

    /** Header-only, like the local-store filter: {@link SessionCookieWebFilter} ran first. */
    private static String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) return null;
        String trimmed = authHeader.trim();
        if (!trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        String candidate = trimmed.substring(7).trim();
        return candidate.startsWith(BFF_PREFIX) ? candidate : null;
    }
}

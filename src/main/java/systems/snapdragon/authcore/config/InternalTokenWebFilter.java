package systems.snapdragon.authcore.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Application-layer DEFENCE-IN-DEPTH for the {@code /bff/internal/**} surface — the in-cluster
 * node-to-BFF prefix that is {@code permitAll()} at the Spring authorization layer
 * ({@code SecurityConfig}, the consumer's own — not part of this jar) and otherwise relies
 * SOLELY on the mTLS transport
 * ({@code server.ssl.client-auth=need}) to keep non-cluster callers out. One of those internal
 * endpoints — the desktop sudo ENTITLEMENT read ({@code DesktopSudoEntitlementController},
 * admin-bff — not part of this jar) — leaks per-(subject, device) sudo state, so a SECOND,
 * app-layer credential is layered on top of the transport: this filter requires an
 * env-injected internal-service token header on every {@code /bff/internal/**} request.
 *
 * <h3>fail-closed when configured, no-op when unset (matches the federation token idiom)</h3>
 * The token + header name come from {@code app.internal.token} / {@code app.internal.token-header}
 * (default header {@code X-Internal-Token}), named consistently with the federation
 * {@code internal-token} config ({@code FederationUsernameConfig} / {@code ProfileForwarder}).
 * Mirroring the federation OUTBOUND semantics — where a BLANK token simply means "do not stamp
 * the header" — the INBOUND mirror is: when {@code app.internal.token} is blank/unset (the
 * default for dev/test/CI), this filter is a NO-OP so those runs boot clean and exercise the
 * internal endpoints without a token. When the token IS configured (the in-cluster deployment
 * injects {@code INTERNAL_TOKEN}), it is REQUIRED on every internal request: a missing or
 * mismatched header is rejected fail-closed with {@code 401}. The credential is never logged and
 * never in git (env-injected, default empty).
 *
 * <p>Ordered LATE ({@link Ordered#LOWEST_PRECEDENCE}, the same slot as
 * {@code WorkloadAuthorizationFilter}) so it runs after the security web filter rather than
 * being short-circuited by the {@code permitAll()} authorization decision; the token comparison
 * is constant-time to avoid a timing side-channel.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class InternalTokenWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(InternalTokenWebFilter.class);

    /** The prefix this filter guards — the in-cluster node-to-BFF surface. */
    static final String INTERNAL_PREFIX = "/bff/internal/";

    private final String tokenHeader;
    private final String expectedToken;

    public InternalTokenWebFilter(
            @Value("${app.internal.token-header:X-Internal-Token}") String tokenHeader,
            @Value("${app.internal.token:}") String expectedToken) {
        this.tokenHeader = (tokenHeader == null || tokenHeader.isBlank())
                ? "X-Internal-Token" : tokenHeader;
        this.expectedToken = expectedToken == null ? "" : expectedToken;
    }

    /** Whether the app-layer internal-token check is ARMED (a token is configured). When
     *  unset (dev/test/CI default) the filter is a no-op — matching the federation outbound
     *  "blank token => do not enforce the header" semantics. */
    boolean enforcing() {
        return !expectedToken.isBlank();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith(INTERNAL_PREFIX) || !enforcing()) {
            // not an internal path, or the token is unset (no-op in dev/test/CI) -> pass through.
            return chain.filter(exchange);
        }
        String presented = exchange.getRequest().getHeaders().getFirst(tokenHeader);
        if (presented != null && constantTimeEquals(presented, expectedToken)) {
            return chain.filter(exchange);
        }
        // fail-closed: missing or mismatched internal token -> 401 (never reaches the controller).
        log.warn("[internal-token] DENY {} — missing/mismatched {} on a privileged internal path",
                path, tokenHeader);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    /** Length-independent constant-time comparison (no early-exit timing leak). */
    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return java.security.MessageDigest.isEqual(x, y);
    }
}

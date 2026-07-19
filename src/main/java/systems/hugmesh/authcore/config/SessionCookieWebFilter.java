package systems.hugmesh.authcore.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * A2 COOKIE BRIDGE — the carrier-agnostic dual-READ for the opaque {@code bff_} session
 * token. The token may arrive in EITHER carrier:
 *
 * <ol>
 *   <li>the {@code bff_session} httpOnly cookie (the cookie-mode UIs), read FIRST; else</li>
 *   <li>the legacy {@code Authorization: Bearer bff_...} header (the standalone/mock + the
 *       existing UIs), read second.</li>
 * </ol>
 *
 * Both resolve to the SAME {@code AccountStore.sessionOfToken()} PK lookup. This filter is
 * the cookie -> header NORMALISER: when a {@code bff_} token is present in the cookie AND the
 * request carries NO {@code Authorization} header (or a non-{@code bff_} one), it mutates the
 * request to add {@code Authorization: Bearer <cookieToken>} so the EXISTING
 * {@code @RequestHeader(AUTHORIZATION)} resolution in {@code AuthController#me} (and every
 * other session-reading controller) works UNCHANGED — no controller needs to learn about the
 * cookie carrier.
 *
 * <h3>UNFLAGGED / always-on / backward-compatible</h3>
 * The dual-READ is NOT gated by any flag. A request with only the legacy Bearer header is
 * byte-for-byte unchanged (this filter does nothing — the header already resolves). A request
 * with only the cookie gets the synthesised header. A request with BOTH keeps its real header
 * (the cookie does not override an explicit {@code bff_} Authorization). So enabling the
 * cookie MINT (A2, {@code app.session.cookie.enabled}) is safe to ship dark: even if a cookie
 * is somehow present, READING it has always been correct, and the only NEW behaviour is the
 * cookie being SET (gated) and CSRF being required for cookie-carried mutations (same flag).
 *
 * <h3>Ordering</h3>
 * Runs EARLY ({@link Ordered#HIGHEST_PRECEDENCE} + offset) so the synthesised header is in
 * place before the security web filter chain reads {@code Authorization} (the resource-server
 * filter only acts on a Casdoor JWT bearer, never a {@code bff_} token, so synthesising a
 * {@code bff_} bearer is inert to it) and before the controllers' {@code @RequestHeader}
 * binding.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class SessionCookieWebFilter implements WebFilter {

    /** The httpOnly cookie name the opaque {@code bff_} session token rides in cookie mode. */
    public static final String SESSION_COOKIE = "bff_session";

    /** The opaque session-token prefix — the only tokens this bridge recognises. */
    private static final String TOKEN_PREFIX = "bff_";

    /**
     * Exchange attribute set to {@code Boolean.TRUE} by this bridge when it SYNTHESISES the
     * {@code Authorization: Bearer bff_...} header from the {@code bff_session} cookie (i.e. the
     * request arrived cookie-ONLY, with no real client-sent {@code bff_} Bearer). Downstream
     * security wiring — notably the CSRF require-matcher in the consumer's own
     * {@code SecurityConfig} (not part of this jar) — MUST consult
     * this attribute rather than the (now bridge-mutated) {@code Authorization} header to decide
     * whether a {@code bff_} Bearer is a genuine client-sent carrier. Without it, the bridge's
     * synthesised header would masquerade as a real Bearer and wrongly exempt EVERY cookie-carried
     * mutation from CSRF (CSRF fail-open). When this attribute is TRUE the request is cookie-borne
     * and double-submit CSRF MUST apply.
     */
    public static final String SYNTHESISED_BEARER_ATTR =
            SessionCookieWebFilter.class.getName() + ".SYNTHESISED_BEARER";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String headerAuth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // If the request ALREADY carries a bff_ Bearer header, the legacy carrier wins —
        // do not let a cookie override an explicit Authorization header.
        if (isBffBearer(headerAuth)) {
            return chain.filter(exchange);
        }

        HttpCookie cookie = request.getCookies().getFirst(SESSION_COOKIE);
        String cookieToken = cookie == null ? null : cookie.getValue();
        if (cookieToken == null || !cookieToken.startsWith(TOKEN_PREFIX)) {
            // No usable cookie token -> pass through unchanged (legacy / unauthenticated path).
            return chain.filter(exchange);
        }

        // Cookie carries a bff_ token and there is no bff_ Authorization header: synthesise one
        // so the existing header-based session resolution works unchanged. MARK the exchange so
        // downstream CSRF wiring knows this Bearer is bridge-synthesised (cookie-borne), NOT a
        // real client-sent Bearer — otherwise the synthesised header would wrongly CSRF-exempt
        // the cookie-carried mutation (CSRF fail-open).
        ServerHttpRequest mutated = request.mutate()
                .headers(h -> h.set(HttpHeaders.AUTHORIZATION, "Bearer " + cookieToken))
                .build();
        exchange.getAttributes().put(SYNTHESISED_BEARER_ATTR, Boolean.TRUE);
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private static boolean isBffBearer(String authorizationHeader) {
        return authorizationHeader != null
                && authorizationHeader.startsWith("Bearer ")
                && authorizationHeader.substring(7).trim().startsWith(TOKEN_PREFIX);
    }

    /**
     * Resolve the raw opaque {@code bff_} session token a controller should consult for the
     * MFA leg, from EITHER carrier (cookie FIRST, else the {@code Authorization: Bearer}
     * header). Carrier-agnostic — mirrors the dual-READ this filter normalises. Returns
     * {@code null} when neither carrier holds a {@code bff_} token. Static so any controller
     * can derive the token from its {@code @CookieValue} + {@code @RequestHeader} bindings
     * without re-implementing the precedence.
     */
    public static String bffTokenFrom(String sessionCookieValue, String authorizationHeader) {
        if (sessionCookieValue != null && sessionCookieValue.startsWith(TOKEN_PREFIX)) {
            return sessionCookieValue;
        }
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String t = authorizationHeader.substring(7).trim();
            if (t.startsWith(TOKEN_PREFIX)) {
                return t;
            }
        }
        return null;
    }
}

package systems.hugmesh.authcore.username;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Reactive client over the federation registry's INTERNAL username-availability
 * endpoint — {@code GET /api/federation/username/{candidate}/availability} — the
 * single owner of the ICU confusable/skeleton engine and the
 * {@code username_skeleton} cache.
 *
 * <p>The endpoint is ROLE_SERVICE / internal (not public — it is an enumeration
 * oracle), so the call carries an internal service credential (a Bearer token
 * for the {@code app-admin-bff} service account, or — until that is wired — a
 * shared {@code X-Internal-Token} header). Both are config-driven.
 *
 * <h3>GATED STUB-SEAM (mirrors {@code HomeserverAdminClient} /
 * {@code CasdoorAdminConfig})</h3>
 * <ul>
 *   <li>the reactive {@link WebClient} is always built + injected non-null so
 *       the {@link UsernameGate} has a real collaborator;</li>
 *   <li>gated by {@code federation.username-gate.enabled} (default false) so a
 *       federation-less dev/test/CI run boots clean — when DISABLED the client
 *       short-circuits to {@link UsernameAvailability#available} WITHOUT a call
 *       (the local {@code ReservedNames} fast-path still rejects reserved names
 *       fail-closed, which is the real DB-backed invariant);</li>
 *   <li>fail-CLOSED on a transport/parse error WHEN ENABLED: the confusable
 *       engine lives only in federation, so a failed availability check must
 *       NOT silently mint a confusable username. An enabled-but-erroring call
 *       resolves to a {@code reason="federation-unavailable"} collision the gate
 *       treats as "not available" (it will not mint).</li>
 * </ul>
 */
public class FederationUsernameClient {

    private static final Logger log = LoggerFactory.getLogger(FederationUsernameClient.class);

    private final WebClient http;
    private final boolean enabled;
    private final String internalTokenHeader;
    private final String internalToken;

    public FederationUsernameClient(WebClient http, boolean enabled,
                                    String internalTokenHeader, String internalToken) {
        this.http = http;
        this.enabled = enabled;
        this.internalTokenHeader = internalTokenHeader;
        this.internalToken = internalToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * Ask the federation registry whether {@code candidate} may be minted. When
     * the gate is disabled, resolves to {@link UsernameAvailability#available}
     * without a network call. When enabled, calls the internal endpoint and maps
     * the {@code {available, reason, matchedWith}} body; a transport/parse error
     * resolves FAIL-CLOSED to a {@code federation-unavailable} collision.
     */
    @SuppressWarnings("unchecked")
    public Mono<UsernameAvailability> availability(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            // A blank candidate can never be minted; treat as a collision so the
            // gate refuses rather than silently passing it through.
            return Mono.just(UsernameAvailability.collide(candidate, "invalid", null));
        }
        if (!enabled) {
            return Mono.just(UsernameAvailability.available(candidate));
        }
        return http.get()
                .uri("/api/federation/username/{candidate}/availability", candidate)
                .headers(h -> {
                    if (internalToken != null && !internalToken.isBlank()) {
                        h.set(internalTokenHeader, internalToken);
                    }
                })
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> mapBody(candidate, (Map<String, Object>) body))
                .onErrorResume(e -> {
                    // FAIL-CLOSED: the confusable engine is only in federation, so
                    // we must NOT mint a possibly-confusable username on an error.
                    log.warn("[username-gate] federation availability for '{}' failed; "
                            + "FAIL-CLOSED (will not mint): {}", candidate, e.toString());
                    return Mono.just(UsernameAvailability.collide(
                            candidate, "federation-unavailable", null));
                });
    }

    private static UsernameAvailability mapBody(String candidate, Map<String, Object> body) {
        if (body == null) {
            return UsernameAvailability.collide(candidate, "federation-unavailable", null);
        }
        boolean available = Boolean.TRUE.equals(body.get("available"))
                // Tolerate a {collide:true} dialect.
                && !Boolean.TRUE.equals(body.get("collide"));
        if (available) {
            return UsernameAvailability.available(candidate);
        }
        String reason = asString(body.get("reason"));
        String matchedWith = asString(body.get("matchedWith"));
        return UsernameAvailability.collide(candidate, reason == null ? "collide" : reason, matchedWith);
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }
}

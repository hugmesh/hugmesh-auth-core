package net.hugmesh.authcore.username;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.Supplier;

/**
 * Reactive client over the federation registry's INTERNAL username-availability
 * endpoint — {@code GET /api/federation/username/{candidate}/availability} — the
 * single owner of the ICU confusable/skeleton engine and the
 * {@code username_skeleton} cache.
 *
 * <h3>Credential — a ROLE_SERVICE bearer, NOT a shared header</h3>
 * The endpoint is an enumeration oracle, so hugmesh-federation-api gates
 * {@code /api/federation/username/**} to {@code ROLE_SERVICE}/{@code ADMIN}/
 * {@code SUPERADMIN} and authenticates EXCLUSIVELY as an OAuth2 resource server
 * (a validated Casdoor JWT in {@code Authorization: Bearer}). It has no
 * {@code X-Internal-Token} filter at all — that header idiom belongs to the
 * admin-bff {@code /bff/internal/**} surface, not to federation. This class
 * therefore presents a Casdoor SERVICE bearer minted for the calling service's
 * own application via the client-credentials grant
 * ({@link net.hugmesh.authcore.casdoor.CasdoorServiceTokenClient}), supplied as
 * "a current bearer per call" so caching/re-minting stays the supplier's job.
 *
 * <p>The legacy {@code internalTokenHeader}/{@code internalToken} pair is kept
 * for wire compatibility: when configured it is STILL stamped alongside the
 * bearer, but on its own it cannot authenticate against federation — a gate that
 * is enabled with no service bearer fails every check CLOSED (see
 * {@link FederationUsernameConfig}, which WARNs loudly about exactly that).
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
 *   <li>fail-CLOSED on a mint, transport, status, empty-body or parse error WHEN
 *       ENABLED: the confusable engine lives only in federation, so a failed
 *       availability check must NOT silently mint a confusable username. An
 *       enabled-but-erroring call resolves to a {@code reason="federation-unavailable"}
 *       collision the gate treats as "not available" (it will not mint).</li>
 * </ul>
 */
public class FederationUsernameClient {

    private static final Logger log = LoggerFactory.getLogger(FederationUsernameClient.class);
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() { };
    private static final String UNAVAILABLE = "federation-unavailable";

    private final WebClient http;
    private final boolean enabled;
    private final String internalTokenHeader;
    private final String internalToken;
    /** Supplies a current ROLE_SERVICE bearer per call; {@code null} = legacy header-only wiring. */
    private final Supplier<Mono<String>> serviceBearer;

    /**
     * Legacy wiring — header-only, NO service bearer. Retained so existing consumers and tests
     * keep compiling; against the real federation-api this credential cannot authenticate, so
     * an ENABLED client built this way fails every check closed.
     */
    public FederationUsernameClient(WebClient http, boolean enabled,
                                    String internalTokenHeader, String internalToken) {
        this(http, enabled, internalTokenHeader, internalToken, null);
    }

    /**
     * @param http                WebClient pre-pointed at federation-api's base URL
     * @param enabled             the {@code federation.username-gate.enabled} gate
     * @param internalTokenHeader legacy header name (stamped only when {@code internalToken} is set)
     * @param internalToken       legacy shared secret; blank/null = do not stamp
     * @param serviceBearer       supplies a current Casdoor ROLE_SERVICE bearer per call; may be
     *                            {@code null} for the legacy header-only wiring
     */
    public FederationUsernameClient(WebClient http, boolean enabled,
                                    String internalTokenHeader, String internalToken,
                                    Supplier<Mono<String>> serviceBearer) {
        this.http = http;
        this.enabled = enabled;
        this.internalTokenHeader = internalTokenHeader;
        this.internalToken = internalToken;
        this.serviceBearer = serviceBearer;
    }

    public boolean enabled() {
        return enabled;
    }

    /** True when a ROLE_SERVICE bearer supplier is wired (the only credential federation accepts). */
    public boolean serviceBearerConfigured() {
        return serviceBearer != null;
    }

    /** Package-private test seam: the wired bearer supplier (may be null). */
    Supplier<Mono<String>> serviceBearer() {
        return serviceBearer;
    }

    /**
     * Ask the federation registry whether {@code candidate} may be minted. When
     * the gate is disabled, resolves to {@link UsernameAvailability#available}
     * without a network call. When enabled, obtains a service bearer (if wired),
     * calls the internal endpoint and maps the {@code {available, reason, matchedWith}}
     * body; a mint/transport/status/empty-body/parse error resolves FAIL-CLOSED to a
     * {@code federation-unavailable} collision.
     */
    public Mono<UsernameAvailability> availability(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            // A blank candidate can never be minted; treat as a collision so the
            // gate refuses rather than silently passing it through.
            return Mono.just(UsernameAvailability.collide(candidate, "invalid", null));
        }
        if (!enabled) {
            return Mono.just(UsernameAvailability.available(candidate));
        }
        Mono<UsernameAvailability> call = serviceBearer == null
                ? fetch(candidate, null)
                : serviceBearer.get()
                        .switchIfEmpty(Mono.error(() -> new IllegalStateException(
                                "service bearer supplier produced no token")))
                        .flatMap(token -> fetch(candidate, token));
        return call.onErrorResume(e -> failClosed(candidate, e));
    }

    private Mono<UsernameAvailability> fetch(String candidate, String bearer) {
        return http.get()
                .uri("/api/federation/username/{candidate}/availability", candidate)
                .headers(h -> stampCredentials(h, bearer))
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .map(body -> mapBody(candidate, body))
                // An empty 2xx body is not an answer; never mistake it for "available".
                .defaultIfEmpty(UsernameAvailability.collide(candidate, UNAVAILABLE, null));
    }

    private void stampCredentials(HttpHeaders h, String bearer) {
        if (bearer != null && !bearer.isBlank()) {
            h.setBearerAuth(bearer);
        }
        if (internalToken != null && !internalToken.isBlank()) {
            h.set(internalTokenHeader, internalToken);
        }
    }

    private static Mono<UsernameAvailability> failClosed(String candidate, Throwable e) {
        // FAIL-CLOSED: the confusable engine is only in federation, so we must NOT
        // mint a possibly-confusable username on an error (including a bearer mint failure).
        log.warn("[username-gate] federation availability for '{}' failed; "
                + "FAIL-CLOSED (will not mint): {}", candidate, e.toString());
        return Mono.just(UsernameAvailability.collide(candidate, UNAVAILABLE, null));
    }

    private static UsernameAvailability mapBody(String candidate, Map<String, Object> body) {
        if (body == null) {
            return UsernameAvailability.collide(candidate, UNAVAILABLE, null);
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

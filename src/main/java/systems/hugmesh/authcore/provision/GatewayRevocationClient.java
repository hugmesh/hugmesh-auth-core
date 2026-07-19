package systems.hugmesh.authcore.provision;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Best-effort HTTP client for the gateway's internal revocation write surface
 * ({@code POST /api/gateway/revocations}, {@code DELETE /api/gateway/revocations/{key}}).
 * Used by admin-bff to:
 * <ol>
 *   <li>Write a coarse homeserver ban key ({@code hs:<platform>:<localpart>}) when
 *       ROLE_MATRIX or ROLE_MASTODON is suspended — a single key on the gateway's
 *       revocation list denies ALL tokens for that localpart on that platform regardless
 *       of which device or app minted them. This is the "coarse revoke" that pairs with
 *       the per-token hs_tokens write (the fine-grained table the filter resolves a
 *       bearer to its identity so per-token revocation works).</li>
 *   <li>Lift the ban key when the suspension is cleared (the restore path).</li>
 * </ol>
 *
 * <p>The gateway's {@code GatewayRevocationController} persists the key to Cassandra
 * ({@code hugmesh_gateway.revocations}) and immediately reflects it on the receiving
 * pod; other gateway pods converge on their next poll tick (≈
 * {@code app.revocation.refresh-interval-ms}, default 5 s). This means a ban
 * propagates to all gateway replicas within one poll cycle rather than only one pod
 * seeing the request.
 *
 * <p><b>Security.</b> The gateway endpoint requires {@code ROLE_ADMIN}. This client
 * presents the admin-bff's own service-account JWT (issued by Casdoor with the admin
 * role), which the gateway's resource-server config accepts. For in-cluster calls the
 * JWT is sourced from the request's {@code Authorization} header passed through; for
 * background loop calls (ban→revoke triggered from the reconcile tick, not an HTTP
 * request) a service-account token is injected separately — see
 * {@code broker.gateway-url} + {@code broker.gateway-service-token}.
 *
 * <p><b>Best-effort.</b> A failed call is LOGGED and swallowed — the authoritative ban
 * state is the {@code access_suspension} Postgres row (which the single-writer reconcile
 * loop already wrote). The gateway's revocation poll also re-reads Cassandra every tick,
 * so even a transient failure here is self-healing once the row is written. The caller
 * MUST NOT propagate the error to the user.
 *
 * <p>Gated by {@code broker.gateway-revocation.enabled} (default {@code false}).
 * When disabled all writes are logged and skipped so a gateway-less dev/test/CI run
 * boots clean. Flip {@code true} (and set {@code BROKER_GATEWAY_URL}) once the gateway
 * {@code GatewayRevocationController} endpoint is reachable from admin-bff.
 */
@Component
public class GatewayRevocationClient {

    private static final Logger log = LoggerFactory.getLogger(GatewayRevocationClient.class);

    /** Default TTL: 30 days — matches the hs_tokens table TTL (2592000 s). Most homeserver
     *  access tokens are shorter-lived; this is a backstop ceiling so the key outlives the
     *  token it gates even if the token was just minted. */
    private static final long DEFAULT_TTL_SECONDS = 2_592_000L;

    private final boolean enabled;
    private final WebClient client;

    public GatewayRevocationClient(
            @Value("${broker.gateway-revocation.enabled:false}") boolean enabled,
            @Value("${broker.gateway-url:http://hugmesh-pki-gateway.hugmesh-pki.svc.cluster.local:8080}") String gatewayUrl) {
        this.enabled = enabled;
        this.client = WebClient.builder().baseUrl(gatewayUrl).build();
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * POST a coarse homeserver ban key to the gateway revocation list. The key shape
     * is {@code hs:<platform>:<localpart>} (e.g. {@code hs:matrix:alice}), which the
     * gateway's {@code HomeserverTokenRevocationFilter} matches against ALL tokens for
     * that localpart on that platform, regardless of device or app.
     *
     * <p>Best-effort: errors are swallowed (logged). The authoritative ban state is
     * the {@code access_suspension} table; this is the fast-path propagation to the
     * in-memory revocation cache.
     *
     * @param platform  {@code matrix} or {@code mastodon}
     * @param localpart the homeserver localpart to ban
     * @param reason    human-readable reason stored in Cassandra (may be null)
     * @param ttlSeconds TTL for the Cassandra row (use 0 or negative to take the
     *                   table default). Should be {@code >=} the longest remaining
     *                   token lifetime for the user.
     */
    public Mono<Void> revokeCoarse(String platform, String localpart, String reason, long ttlSeconds) {
        String key = "hs:" + platform + ":" + localpart;
        return postRevocation(key, reason, ttlSeconds)
                .onErrorResume(e -> {
                    log.warn("[gateway-revocation] best-effort revokeCoarse({}) failed (ban still in DB): {}",
                            key, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * POST a per-subject revocation key to the gateway revocation list. The key shape
     * is {@code subject:<casdoorSub>} (e.g. {@code subject:alice}), which the gateway's
     * {@code RevocationGatewayFilter} matches against the JWT {@code sub} (or {@code id})
     * claim on every authenticated request — denying ALL custody JWTs minted for that
     * Casdoor user until the key expires.
     *
     * <p>Use cases:
     * <ul>
     *   <li><b>Role revoke</b> — when an admin revokes a role directly (via
     *       {@code DELETE /bff/admin/roles/{role}/{user}}) the user's live custody JWT
     *       retains the role for up to its natural TTL (default 1 h). Writing
     *       {@code subject:<user>} here closes that window: the gateway denies the
     *       stale JWT until it (and this key) naturally expire.</li>
     *   <li><b>Suspension + role-drop</b> — complements the coarse homeserver ban
     *       ({@link #revokeCoarse}) by also invalidating the custody JWT for the
     *       suspended user, not just their homeserver tokens.</li>
     * </ul>
     *
     * <p>The TTL should be {@code >=} the custody JWT lifetime (default 3 600 s / 1 h)
     * so the revocation key outlives any stale JWT in flight.
     *
     * <p>Best-effort: errors are swallowed (logged). The authoritative desired-state
     * is the {@code access_suspension} row / Casdoor membership; this is the
     * fast-path propagation to the in-memory revocation cache.
     *
     * @param casdoorSub the Casdoor user's subject identifier (JWT {@code sub} / {@code id})
     * @param reason     human-readable reason stored in Cassandra (may be null)
     * @param ttlSeconds TTL for the Cassandra row; must be {@code >= custody JWT lifetime}.
     *                   Use 0 or negative to take the table default (30 days).
     */
    public Mono<Void> revokeSubject(String casdoorSub, String reason, long ttlSeconds) {
        String key = "subject:" + casdoorSub;
        return postRevocation(key, reason, ttlSeconds)
                .onErrorResume(e -> {
                    log.warn("[gateway-revocation] best-effort revokeSubject({}) failed: {}",
                            key, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * DELETE the coarse ban key from the gateway revocation list (the restore path:
     * un-ban, suspension expiry). The gateway drops the key on this pod immediately;
     * other pods converge on their next poll tick.
     *
     * <p>Best-effort: errors are swallowed (logged).
     *
     * @param platform  {@code matrix} or {@code mastodon}
     * @param localpart the homeserver localpart whose ban is being lifted
     */
    public Mono<Void> clearCoarse(String platform, String localpart) {
        String key = "hs:" + platform + ":" + localpart;
        return deleteRevocation(key)
                .onErrorResume(e -> {
                    log.warn("[gateway-revocation] best-effort clearCoarse({}) failed (restore still in DB): {}",
                            key, e.toString());
                    return Mono.empty();
                });
    }

    // ── internals ─────────────────────────────────────────────────────────────

    private Mono<Void> postRevocation(String key, String reason, long ttlSeconds) {
        if (!enabled) {
            log.debug("[gateway-revocation] STUB (gateway-revocation.enabled=false): POST key={}", key);
            return Mono.empty();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("key", key);
        if (reason != null) body.put("reason", reason);
        body.put("ttlSeconds", ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS);
        log.debug("[gateway-revocation] POST /api/gateway/revocations key={}", key);
        return client.post().uri("/api/gateway/revocations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .then();
    }

    private Mono<Void> deleteRevocation(String key) {
        if (!enabled) {
            log.debug("[gateway-revocation] STUB (gateway-revocation.enabled=false): DELETE key={}", key);
            return Mono.empty();
        }
        log.debug("[gateway-revocation] DELETE /api/gateway/revocations/{}", key);
        return client.delete().uri("/api/gateway/revocations/{key}", key)
                .retrieve()
                .toBodilessEntity()
                .then();
    }
}

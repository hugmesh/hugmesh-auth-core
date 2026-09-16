package net.hugmesh.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * A caching OAuth2 <b>client-credentials</b> client against Casdoor's token endpoint
 * ({@code POST /api/login/oauth/access_token}) that supplies "a current ROLE_SERVICE bearer"
 * to every internal service-to-service caller in this jar.
 *
 * <p>This is the canonical HugMesh mechanism for an internal {@code ROLE_SERVICE} surface:
 * the caller mints a Casdoor JWT for ITS OWN application (never a human's token) with the
 * {@code app.casdoor.platform.{base-url,client-id,client-secret}} credentials the service
 * already holds, and presents it as {@code Authorization: Bearer}. The shape — including the
 * 60 s re-mint skew and the 30 min fallback lifetime — is byte-for-byte the
 * {@code serviceTokenSupplier} hugmesh-actions ({@code FederationUsernameClientConfig}) and
 * admin-bff ({@code UserBffNotificationConfig}, {@code FederationOverrideClearConfig}) each
 * carry as a private copy; this class is the first shared one, so a future consumer can
 * inject it instead of pasting a fourth copy.
 *
 * <p><b>Caching.</b> The last minted token is held with the instant it becomes stale
 * ({@code now + expires_in - EXPIRY_SKEW}, or {@code now + DEFAULT_TTL - EXPIRY_SKEW} when
 * Casdoor omits {@code expires_in}) and is re-minted only once stale. Concurrent callers that
 * both observe a stale cache each mint — a benign double-mint, never a wrong token. The token
 * is never logged.
 *
 * <p><b>Failure.</b> A transport error, a non-2xx status, or a 2xx body without a non-blank
 * {@code access_token} surfaces as an error on the returned {@link Mono}; the caller decides
 * what that means (the username gate treats it as FAIL-CLOSED).
 */
public class CasdoorServiceTokenClient implements Supplier<Mono<String>> {

    /** Casdoor's OAuth2 token endpoint, relative to the platform Casdoor base URL. */
    public static final String TOKEN_PATH = "/api/login/oauth/access_token";
    /** Re-mint this long before the stated expiry so a call never races the clock. */
    static final Duration EXPIRY_SKEW = Duration.ofSeconds(60);
    /** Fallback lifetime when Casdoor omits {@code expires_in}. */
    static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    private static final Logger log = LoggerFactory.getLogger(CasdoorServiceTokenClient.class);
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() { };

    private final WebClient casdoor;
    private final String clientId;
    private final String clientSecret;
    private final Clock clock;
    private final AtomicReference<Cached> cache = new AtomicReference<>();

    /**
     * @param casdoor      WebClient pre-pointed at the platform Casdoor base URL
     * @param clientId     the calling service's Casdoor application client id
     * @param clientSecret the calling service's Casdoor application client secret (env-injected)
     */
    public CasdoorServiceTokenClient(WebClient casdoor, String clientId, String clientSecret) {
        this(casdoor, clientId, clientSecret, Clock.systemUTC());
    }

    /** Test seam: the clock that decides staleness. */
    CasdoorServiceTokenClient(WebClient casdoor, String clientId, String clientSecret, Clock clock) {
        this.casdoor = casdoor;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clock = clock;
    }

    /** The Casdoor application this client mints for (not a secret; useful for diagnostics). */
    public String clientId() {
        return clientId;
    }

    /** A current bearer: the cached one while fresh, else a freshly minted one. */
    @Override
    public Mono<String> get() {
        return Mono.defer(this::currentOrMint);
    }

    private Mono<String> currentOrMint() {
        Cached c = cache.get();
        if (c != null && clock.instant().isBefore(c.staleAt())) {
            return Mono.just(c.token());
        }
        return mint();
    }

    private Mono<String> mint() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return casdoor.post()
                .uri(TOKEN_PATH)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .switchIfEmpty(Mono.error(() -> new IllegalStateException(
                        "casdoor token mint returned an empty body")))
                .flatMap(this::cacheAndReturn);
    }

    /** Extract {@code access_token} + TTL from the Casdoor token response, cache it, return it. */
    private Mono<String> cacheAndReturn(Map<String, Object> json) {
        Object at = json.get("access_token");
        if (!(at instanceof String token) || token.isBlank()) {
            return Mono.error(new IllegalStateException("casdoor token mint returned no access_token"));
        }
        Object exp = json.get("expires_in");
        long expiresIn = exp instanceof Number num ? num.longValue() : 0L;
        Duration ttl = expiresIn > 0 ? Duration.ofSeconds(expiresIn) : DEFAULT_TTL;
        Instant staleAt = clock.instant().plus(ttl).minus(EXPIRY_SKEW);
        cache.set(new Cached(token, staleAt));
        log.debug("[casdoor-service-token] minted bearer for client '{}' (stale at {})", clientId, staleAt);
        return Mono.just(token);
    }

    private record Cached(String token, Instant staleAt) { }
}

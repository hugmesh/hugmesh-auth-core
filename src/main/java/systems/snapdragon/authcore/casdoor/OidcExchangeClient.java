package systems.snapdragon.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Reactive client for the Casdoor OIDC token endpoint
 * ({@code {issuer}/api/login/oauth/access_token}). It performs the two server-side legs of the
 * BFF-JWT-custody flow WITHOUT pulling in {@code spring-security-oauth2-client} (the BFF owns
 * the session lifecycle; it does not delegate to Spring's OAuth2 login machinery):
 *
 * <ol>
 *   <li>{@link #exchangeCode} — the PKCE authorization-code exchange the user-bff
 *       {@code /bff/auth/callback} performs after login-ui redirects back with {@code code}.</li>
 *   <li>{@link #refresh} — the {@code grant_type=refresh_token} leg the admin-bff
 *       {@code /bff/internal/session/exchange} endpoint uses to lazily re-mint a held access
 *       token before it expires (and that {@link RawJwtRefreshService} delegates to).</li>
 * </ol>
 *
 * <p>The returned {@link OidcTokens} are SECRET and are immediately custody-encrypted by the
 * caller ({@link BffCustodyCipher}); they never reach the browser. The bean is gated behind
 * {@code app.bff.oidc.enabled} (default false) by {@link OidcExchangeConfig}, so a non-OIDC
 * deployment never instantiates it and its consumers inject {@code @Nullable ... = null}.
 */
public class OidcExchangeClient {

    private static final Logger log = LoggerFactory.getLogger(OidcExchangeClient.class);

    private final WebClient http;
    private final String tokenPath;
    private final String clientId;
    private final String clientSecret;
    private final long defaultExpirySeconds;

    public OidcExchangeClient(String issuerBaseUrl, String tokenPath, String clientId,
                              String clientSecret, long defaultExpirySeconds) {
        this.http = WebClient.builder().baseUrl(issuerBaseUrl).build();
        this.tokenPath = tokenPath;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.defaultExpirySeconds = defaultExpirySeconds;
    }

    /** Test seam — inject a pre-built WebClient (e.g. backed by a stub exchange). */
    OidcExchangeClient(WebClient http, String tokenPath, String clientId, String clientSecret,
                       long defaultExpirySeconds) {
        this.http = http;
        this.tokenPath = tokenPath;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.defaultExpirySeconds = defaultExpirySeconds;
    }

    /**
     * Exchange a PKCE authorization {@code code} for tokens. The {@code redirectUri} MUST match
     * the one used in the authorization request; {@code codeVerifier} is the PKCE verifier whose
     * SHA-256 challenge was sent on the authorize call.
     */
    public Mono<OidcTokens> exchangeCode(String code, String codeVerifier, String redirectUri) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        if (codeVerifier != null && !codeVerifier.isBlank()) {
            form.add("code_verifier", codeVerifier);
        }
        return post(form, "authorization_code");
    }

    /** Exchange a held {@code refresh_token} for a fresh access token (+ rotated refresh token). */
    public Mono<OidcTokens> refresh(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return post(form, "refresh_token");
    }

    @SuppressWarnings("unchecked")
    private Mono<OidcTokens> post(MultiValueMap<String, String> form, String grant) {
        return http.post()
                .uri(tokenPath)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> {
                    Object err = body.get("error");
                    if (err != null) {
                        // Never log the form (carries client_secret/code); only the grant + error code.
                        throw new IllegalStateException("OIDC token endpoint returned error for "
                                + grant + ": " + err);
                    }
                    String access = str(body.get("access_token"));
                    String refresh = str(body.get("refresh_token"));
                    String id = str(body.get("id_token"));
                    long expires = body.get("expires_in") instanceof Number n
                            ? n.longValue() : defaultExpirySeconds;
                    return new OidcTokens(access, refresh, id, expires);
                });
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }
}

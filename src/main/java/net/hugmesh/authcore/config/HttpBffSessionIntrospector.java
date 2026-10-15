package net.hugmesh.authcore.config;

import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * {@link BffSessionIntrospector} over HTTP: {@code GET /bff/internal/session/introspect} on
 * admin-bff with the session token as {@code Authorization: Bearer}. The supplied
 * {@link WebClient} owns the base URL and whatever service credential the internal surface
 * demands ({@code X-Internal-Token}, mTLS); this class adds only the session token.
 *
 * <p>A {@code 401} (admin-bff's answer for an unknown or expired session) becomes an EMPTY
 * result; every other non-2xx status or transport failure stays an error.
 */
public class HttpBffSessionIntrospector implements BffSessionIntrospector {

    /** Path of admin-bff's internal introspection endpoint. */
    public static final String INTROSPECT_PATH = "/bff/internal/session/introspect";

    private final WebClient http;

    public HttpBffSessionIntrospector(WebClient http) {
        this.http = http;
    }

    @Override
    public Mono<BffSessionIntrospection> introspect(String bffToken) {
        return http.get()
                .uri(INTROSPECT_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bffToken)
                .retrieve()
                .bodyToMono(BffSessionIntrospection.class)
                .onErrorResume(WebClientResponseException.Unauthorized.class, e -> Mono.empty());
    }
}

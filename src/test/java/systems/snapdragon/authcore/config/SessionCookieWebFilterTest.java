package systems.snapdragon.authcore.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A2 dual-READ bridge — proves BOTH carriers (the {@code bff_session} httpOnly cookie and the
 * legacy {@code Authorization: Bearer bff_} header) end up presenting the SAME token to the
 * downstream chain, so the existing header-based session resolution is unchanged, and the
 * carrier-agnostic {@link SessionCookieWebFilter#bffTokenFrom} precedence is correct.
 */
class SessionCookieWebFilterTest {

    private final SessionCookieWebFilter filter = new SessionCookieWebFilter();

    /** Run the filter and capture the Authorization header the downstream chain sees. */
    private String downstreamAuth(ServerWebExchange exchange) {
        AtomicReference<String> seen = new AtomicReference<>();
        filter.filter(exchange, ex -> {
            seen.set(ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            return Mono.empty();
        }).block();
        return seen.get();
    }

    @Test
    void cookieCarrier_synthesisesBearerHeader() {
        ServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get("/bff/me").cookie(
                        new org.springframework.http.HttpCookie(
                                SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")));
        assertThat(downstreamAuth(ex)).isEqualTo("Bearer bff_abc");
    }

    @Test
    void bearerCarrier_passesThroughUnchanged() {
        ServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get("/bff/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bff_xyz"));
        assertThat(downstreamAuth(ex)).isEqualTo("Bearer bff_xyz");
    }

    @Test
    void bothCarriers_bearerHeaderWins_cookieDoesNotOverride() {
        ServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get("/bff/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bff_header")
                        .cookie(new org.springframework.http.HttpCookie(
                                SessionCookieWebFilter.SESSION_COOKIE, "bff_cookie")));
        assertThat(downstreamAuth(ex)).isEqualTo("Bearer bff_header");
    }

    @Test
    void noCarrier_passesThroughWithNoHeader() {
        ServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get("/bff/me"));
        assertThat(downstreamAuth(ex)).isNull();
    }

    @Test
    void nonBffCookie_ignored() {
        // A cookie value that is not a bff_ token is not synthesised into a header.
        ServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.GET, "/bff/me").cookie(
                        new org.springframework.http.HttpCookie(
                                SessionCookieWebFilter.SESSION_COOKIE, "not-a-bff-token")));
        assertThat(downstreamAuth(ex)).isNull();
    }

    @Test
    void bffTokenFrom_cookieFirst_thenHeader() {
        // cookie first
        assertThat(SessionCookieWebFilter.bffTokenFrom("bff_cookie", "Bearer bff_header"))
                .isEqualTo("bff_cookie");
        // header fallback when no cookie
        assertThat(SessionCookieWebFilter.bffTokenFrom(null, "Bearer bff_header"))
                .isEqualTo("bff_header");
        // neither -> null
        assertThat(SessionCookieWebFilter.bffTokenFrom(null, null)).isNull();
        // non-bff carriers -> null
        assertThat(SessionCookieWebFilter.bffTokenFrom("sessionish", "Bearer ey.jwt")).isNull();
    }
}

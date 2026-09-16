package net.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The shared client-credentials bearer minter: the exact form POST Casdoor expects, the
 * cache-until-stale contract (driven by an injected clock, so staleness is PROVEN rather than
 * slept for), the {@code expires_in} fallback, and that every failure surfaces as an error
 * rather than an empty or bogus token.
 */
class CasdoorServiceTokenClientTest {

    /** A clock the test moves by hand. */
    static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            this.now = new AtomicReference<>(start);
        }

        void advance(Duration d) {
            now.updateAndGet(i -> i.plus(d));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    /** Records every outgoing request and answers with a canned token body / status. */
    static final class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String body = "{\"access_token\":\"svc-jwt\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        HttpStatus status = HttpStatus.OK;
        boolean fail = false;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (fail) {
                return Mono.error(new RuntimeException("connection refused"));
            }
            return Mono.just(ClientResponse.create(status)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(body).build());
        }
    }

    private static final Instant T0 = Instant.parse("2026-09-16T12:00:00Z");

    private static CasdoorServiceTokenClient client(Recorder rec, Clock clock) {
        WebClient casdoor = WebClient.builder().baseUrl("http://casdoor:8000").exchangeFunction(rec).build();
        return new CasdoorServiceTokenClient(casdoor, "app-admin-bff", "s3cret", clock);
    }

    /** Render the recorded request's body the way the wire would see it. */
    private static String formBodyOf(ClientRequest request) {
        MockClientHttpRequest sink = new MockClientHttpRequest(request.method(), request.url());
        request.writeTo(sink, ExchangeStrategies.withDefaults()).block();
        return sink.getBodyAsString().block();
    }

    @Test
    @DisplayName("mints with a client_credentials FORM POST to Casdoor's token endpoint")
    void mints_viaClientCredentialsForm() {
        Recorder rec = new Recorder();
        StepVerifier.create(client(rec, new MutableClock(T0)).get())
                .expectNext("svc-jwt").verifyComplete();

        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        // The LITERAL path Casdoor serves, not the constant: asserting against TOKEN_PATH itself
        // is a tautology (a mutated constant still passed 9/9 — measured 2026-09-16).
        assertThat(req.url().getPath()).isEqualTo("/api/login/oauth/access_token");
        assertThat(req.headers().getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        String form = formBodyOf(req);
        assertThat(form).contains("grant_type=client_credentials");
        assertThat(form).contains("client_id=app-admin-bff");
        assertThat(form).contains("client_secret=s3cret");
        // Never a Basic header — Casdoor's token endpoint takes the secret in the form body.
        assertThat(req.headers().getFirst("Authorization")).isNull();
    }

    @Test
    @DisplayName("second get() serves the cached token — no second mint")
    void secondGet_servesCache_noSecondMint() {
        Recorder rec = new Recorder();
        CasdoorServiceTokenClient c = client(rec, new MutableClock(T0));
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    @DisplayName("re-mints once the token is within EXPIRY_SKEW of expires_in, not before")
    void staleToken_isReminted_notBefore() {
        Recorder rec = new Recorder();
        MutableClock clock = new MutableClock(T0);
        CasdoorServiceTokenClient c = client(rec, clock);
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();

        // expires_in=3600 → stale at +3540s. One second before: still cached.
        clock.advance(Duration.ofSeconds(3600).minus(CasdoorServiceTokenClient.EXPIRY_SKEW).minusSeconds(1));
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        assertThat(rec.requests).hasSize(1);

        // Cross the stale instant: re-mint, and the NEW token is what comes back.
        rec.body = "{\"access_token\":\"svc-jwt-2\",\"expires_in\":3600}";
        clock.advance(Duration.ofSeconds(1));
        StepVerifier.create(c.get()).expectNext("svc-jwt-2").verifyComplete();
        assertThat(rec.requests).hasSize(2);
    }

    @Test
    @DisplayName("expires_in absent → DEFAULT_TTL governs staleness")
    void missingExpiresIn_usesDefaultTtl() {
        Recorder rec = new Recorder();
        rec.body = "{\"access_token\":\"svc-jwt\"}";
        MutableClock clock = new MutableClock(T0);
        CasdoorServiceTokenClient c = client(rec, clock);
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();

        clock.advance(CasdoorServiceTokenClient.DEFAULT_TTL
                .minus(CasdoorServiceTokenClient.EXPIRY_SKEW).minusSeconds(1));
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        assertThat(rec.requests).hasSize(1);

        clock.advance(Duration.ofSeconds(1));
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        assertThat(rec.requests).hasSize(2);
    }

    @Test
    @DisplayName("a 2xx body with no access_token is an error, never an empty/blank bearer")
    void noAccessToken_errors() {
        Recorder rec = new Recorder();
        rec.body = "{\"error\":\"invalid_client\"}";
        StepVerifier.create(client(rec, new MutableClock(T0)).get())
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("no access_token"))
                .verify();
    }

    @Test
    @DisplayName("a blank access_token is an error too")
    void blankAccessToken_errors() {
        Recorder rec = new Recorder();
        rec.body = "{\"access_token\":\"  \"}";
        StepVerifier.create(client(rec, new MutableClock(T0)).get())
                .expectError(IllegalStateException.class).verify();
    }

    @Test
    @DisplayName("a non-2xx from Casdoor is an error (and nothing is cached)")
    void httpError_errors_andCachesNothing() {
        Recorder rec = new Recorder();
        rec.status = HttpStatus.UNAUTHORIZED;
        CasdoorServiceTokenClient c = client(rec, new MutableClock(T0));
        StepVerifier.create(c.get()).expectError(WebClientResponseException.class).verify();
        // Recovery: the next call mints again rather than serving a poisoned cache.
        rec.status = HttpStatus.OK;
        StepVerifier.create(c.get()).expectNext("svc-jwt").verifyComplete();
        assertThat(rec.requests).hasSize(2);
    }

    @Test
    @DisplayName("a transport failure is an error")
    void transportFailure_errors() {
        Recorder rec = new Recorder();
        rec.fail = true;
        StepVerifier.create(client(rec, new MutableClock(T0)).get())
                .expectError(RuntimeException.class).verify();
    }

    @Test
    void clientId_isExposedForDiagnostics_secretIsNot() {
        CasdoorServiceTokenClient c = client(new Recorder(), new MutableClock(T0));
        assertThat(c.clientId()).isEqualTo("app-admin-bff");
        assertThat(c.toString()).doesNotContain("s3cret");
    }
}

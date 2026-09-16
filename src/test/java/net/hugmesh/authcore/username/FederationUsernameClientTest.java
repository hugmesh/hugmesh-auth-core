package net.hugmesh.authcore.username;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the federation username-availability client: the gated short-circuit
 * (no call when disabled), the {@code {available, reason, matchedWith}} body
 * mapping, the ROLE_SERVICE bearer (the only credential federation-api accepts),
 * the legacy internal-token header, and the FAIL-CLOSED behaviour on a mint,
 * transport, status, empty-body or parse error.
 */
class FederationUsernameClientTest {

    /** Records outgoing requests and replies with a canned availability body. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String body = "{\"available\":true}";
        HttpStatus status = HttpStatus.OK;
        boolean fail = false;
        /** Answer with NO body publisher at all (a 204-style empty Flux, not a zero-byte buffer). */
        boolean noBody = false;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (fail) {
                return Mono.error(new RuntimeException("connection refused"));
            }
            if (noBody) {
                return Mono.just(ClientResponse.create(status).body(Flux.empty()).build());
            }
            return Mono.just(ClientResponse.create(status)
                    .header("Content-Type", "application/json")
                    .body(body).build());
        }
    }

    private static WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://federation").exchangeFunction(rec).build();
    }

    /** Legacy 4-arg wiring: header-only, no service bearer. */
    private FederationUsernameClient client(Recorder rec, boolean enabled, String token) {
        return new FederationUsernameClient(web(rec), enabled, "X-Internal-Token", token);
    }

    /** Bearer wiring: a supplier of the current ROLE_SERVICE bearer, plus the optional legacy header. */
    private FederationUsernameClient bearerClient(Recorder rec, Supplier<Mono<String>> bearer, String legacyToken) {
        return new FederationUsernameClient(web(rec), true, "X-Internal-Token", legacyToken, bearer);
    }

    // ---- gate / mapping (unchanged contract) -------------------------------------------------

    @Test
    void disabled_returnsAvailableWithoutCalling() {
        Recorder rec = new Recorder();
        UsernameAvailability av = client(rec, false, null).availability("alice").block();

        assertThat(av).isNotNull();
        assertThat(av.available()).isTrue();
        assertThat(rec.requests).isEmpty();   // no network call when gated off
    }

    @Test
    void enabled_available_mapsToAvailableAndSendsToken() {
        Recorder rec = new Recorder();
        rec.body = "{\"available\":true}";
        UsernameAvailability av = client(rec, true, "svc-secret").availability("alice").block();

        assertThat(av.available()).isTrue();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.url().getPath()).isEqualTo("/api/federation/username/alice/availability");
        assertThat(req.headers().getFirst("X-Internal-Token")).isEqualTo("svc-secret");
    }

    @Test
    void enabled_collision_mapsReasonAndMatchedWith() {
        Recorder rec = new Recorder();
        rec.body = "{\"available\":false,\"reason\":\"confusable\",\"matchedWith\":\"alicia\"}";
        UsernameAvailability av = client(rec, true, null).availability("a1icia").block();

        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("confusable");
        assertThat(av.matchedWith()).isEqualTo("alicia");
    }

    @Test
    void enabled_collideDialect_isHonoured() {
        Recorder rec = new Recorder();
        rec.body = "{\"collide\":true,\"reason\":\"exact\",\"matchedWith\":\"bob\"}";
        UsernameAvailability av = client(rec, true, null).availability("bob").block();

        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("exact");
    }

    @Test
    void enabled_transportError_failsClosed() {
        Recorder rec = new Recorder();
        rec.fail = true;
        UsernameAvailability av = client(rec, true, null).availability("alice").block();

        // Fail-CLOSED: an error is NOT mistaken for "available".
        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
    }

    @Test
    @DisplayName("what federation-api actually does to a header-only caller — 401 — fails closed")
    void enabled_unauthorizedStatus_failsClosed() {
        Recorder rec = new Recorder();
        rec.status = HttpStatus.UNAUTHORIZED;
        rec.body = "";
        UsernameAvailability av = client(rec, true, "svc-secret").availability("alice").block();

        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
    }

    @Test
    @DisplayName("an empty 2xx body is not an answer — fails closed, never 'available'")
    void enabled_emptyBody_failsClosed() {
        Recorder rec = new Recorder();
        rec.body = "";
        UsernameAvailability av = client(rec, true, null).availability("alice").block();

        assertThat(av).isNotNull();
        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
    }

    @Test
    @DisplayName("a 204 with NO body publisher (an empty Mono, not a decode error) fails closed too")
    void enabled_noContent_failsClosed() {
        Recorder rec = new Recorder();
        rec.status = HttpStatus.NO_CONTENT;
        rec.noBody = true;
        UsernameAvailability av = client(rec, true, null).availability("alice").block();

        assertThat(av).isNotNull();
        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
    }

    @Test
    void blankCandidate_isCollisionNotMint() {
        UsernameAvailability av = client(new Recorder(), true, null).availability("  ").block();
        assertThat(av.available()).isFalse();
    }

    // ---- the ROLE_SERVICE bearer ------------------------------------------------------------

    @Test
    @DisplayName("bearer wiring sends Authorization: Bearer <token> and no legacy header when none is set")
    void enabled_withServiceBearer_sendsAuthorizationBearer() {
        Recorder rec = new Recorder();
        UsernameAvailability av = bearerClient(rec, () -> Mono.just("svc-jwt"), null)
                .availability("alice").block();

        assertThat(av.available()).isTrue();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.url().getPath()).isEqualTo("/api/federation/username/alice/availability");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer svc-jwt");
        assertThat(req.headers().containsHeader("X-Internal-Token")).isFalse();
    }

    @Test
    @DisplayName("bearer + legacy header configured → both are stamped (wire compatibility)")
    void enabled_withBearerAndLegacyHeader_sendsBoth() {
        Recorder rec = new Recorder();
        bearerClient(rec, () -> Mono.just("svc-jwt"), "svc-secret").availability("alice").block();

        ClientRequest req = rec.requests.get(0);
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer svc-jwt");
        assertThat(req.headers().getFirst("X-Internal-Token")).isEqualTo("svc-secret");
    }

    @Test
    @DisplayName("the supplier is consulted per call, so a re-minted bearer is what goes on the wire")
    void enabled_bearerIsFetchedPerCall() {
        Recorder rec = new Recorder();
        List<String> tokens = new ArrayList<>(List.of("jwt-1", "jwt-2"));
        FederationUsernameClient c = bearerClient(rec, () -> Mono.just(tokens.remove(0)), null);
        c.availability("alice").block();
        c.availability("bob").block();

        assertThat(rec.requests).hasSize(2);
        assertThat(rec.requests.get(0).headers().getFirst("Authorization")).isEqualTo("Bearer jwt-1");
        assertThat(rec.requests.get(1).headers().getFirst("Authorization")).isEqualTo("Bearer jwt-2");
    }

    @Test
    @DisplayName("a bearer mint failure fails CLOSED and federation is never called")
    void enabled_bearerMintFails_failsClosed_withoutCallingFederation() {
        Recorder rec = new Recorder();
        UsernameAvailability av = bearerClient(rec,
                () -> Mono.error(new IllegalStateException("casdoor token mint returned no access_token")), null)
                .availability("alice").block();

        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
        assertThat(rec.requests).isEmpty();
    }

    @Test
    @DisplayName("a supplier that completes EMPTY is a mint failure, not a silent no-answer")
    void enabled_bearerSupplierEmpty_failsClosed() {
        Recorder rec = new Recorder();
        UsernameAvailability av = bearerClient(rec, Mono::empty, null).availability("alice").block();

        assertThat(av).isNotNull();
        assertThat(av.available()).isFalse();
        assertThat(av.reason()).isEqualTo("federation-unavailable");
        assertThat(rec.requests).isEmpty();
    }

    @Test
    @DisplayName("disabled + bearer wired → still no call, no mint")
    void disabled_withBearer_neverMintsOrCalls() {
        Recorder rec = new Recorder();
        List<String> mints = new ArrayList<>();
        FederationUsernameClient c = new FederationUsernameClient(web(rec), false, "X-Internal-Token", null,
                () -> { mints.add("mint"); return Mono.just("svc-jwt"); });
        UsernameAvailability av = c.availability("alice").block();

        assertThat(av.available()).isTrue();
        assertThat(rec.requests).isEmpty();
        assertThat(mints).isEmpty();
    }

    @Test
    void legacyConstructor_sendsNoAuthorization_andReportsNoBearer() {
        Recorder rec = new Recorder();
        FederationUsernameClient c = client(rec, true, "svc-secret");
        c.availability("alice").block();

        assertThat(c.serviceBearerConfigured()).isFalse();
        assertThat(rec.requests.get(0).headers().containsHeader("Authorization")).isFalse();
        assertThat(bearerClient(rec, () -> Mono.just("x"), null).serviceBearerConfigured()).isTrue();
    }
}

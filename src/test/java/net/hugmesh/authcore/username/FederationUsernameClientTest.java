package net.hugmesh.authcore.username;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the federation username-availability client: the gated short-circuit
 * (no call when disabled), the {@code {available, reason, matchedWith}} body
 * mapping, the internal-token header, and the FAIL-CLOSED behaviour on a
 * transport/parse error.
 */
class FederationUsernameClientTest {

    /** Records outgoing requests and replies with a canned availability body. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String body = "{\"available\":true}";
        HttpStatus status = HttpStatus.OK;
        boolean fail = false;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (fail) {
                return Mono.error(new RuntimeException("connection refused"));
            }
            return Mono.just(ClientResponse.create(status)
                    .header("Content-Type", "application/json")
                    .body(body).build());
        }
    }

    private FederationUsernameClient client(Recorder rec, boolean enabled, String token) {
        WebClient web = WebClient.builder().baseUrl("http://federation").exchangeFunction(rec).build();
        return new FederationUsernameClient(web, enabled, "X-Internal-Token", token);
    }

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
    void blankCandidate_isCollisionNotMint() {
        UsernameAvailability av = client(new Recorder(), true, null).availability("  ").block();
        assertThat(av.available()).isFalse();
    }
}

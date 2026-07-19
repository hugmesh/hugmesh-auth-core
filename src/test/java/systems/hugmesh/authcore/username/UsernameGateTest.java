package systems.hugmesh.authcore.username;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpStatus.OK;

/**
 * The username-derivation gate: the local reserved fast-path (fail-closed,
 * federation never consulted for a reserved name), the federation confusable
 * check, auto-disambiguation on collision, and the hard-reject paths.
 */
class UsernameGateTest {

    /**
     * A {@link FederationUsernameClient} whose backing WebClient answers
     * "unavailable (confusable)" for any candidate in {@code taken} and
     * "available" otherwise — lets the disambiguation walk be asserted exactly.
     */
    private UsernameGate gateWithTaken(Set<String> taken) {
        WebClient web = WebClient.builder().baseUrl("http://federation")
                .exchangeFunction(request -> {
                    String path = request.url().getPath();   // /api/federation/username/{c}/availability
                    String[] parts = path.split("/");
                    String candidate = parts.length >= 5 ? parts[4] : "";
                    String body = taken.contains(candidate)
                            ? "{\"available\":false,\"reason\":\"confusable\",\"matchedWith\":\"" + candidate + "x\"}"
                            : "{\"available\":true}";
                    return Mono.just(ClientResponse.create(OK)
                            .header("Content-Type", "application/json").body(body).build());
                }).build();
        FederationUsernameClient federation =
                new FederationUsernameClient(web, true, "X-Internal-Token", null);
        return new UsernameGate(federation);
    }

    /** Gate with the federation DISABLED — only the local reserved check runs. */
    private UsernameGate gateDisabled() {
        FederationUsernameClient federation =
                new FederationUsernameClient(null, false, "X-Internal-Token", null);
        return new UsernameGate(federation);
    }

    @Test
    void resolve_cleanCandidate_passesThrough() {
        StepVerifier.create(gateWithTaken(Set.of()).resolve("alice"))
                .expectNext("alice")
                .verifyComplete();
    }

    @Test
    void resolve_reservedCandidate_isHardRejectedLocally_neverDisambiguated() {
        // 'admin' is reserved — the gate errors (reason=reserved); it is NEVER
        // renamed to admin2, and federation is never even consulted.
        StepVerifier.create(gateDisabled().resolve("admin"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(UsernameGateException.class);
                    assertThat(((UsernameGateException) e).reason()).isEqualTo("reserved");
                })
                .verify();
    }

    @Test
    void check_reserved_failsClosedWithoutFederation() {
        UsernameAvailability av = gateDisabled().check("vault").block();
        assertThat(av).isNotNull();
        assertThat(av.available()).isFalse();
        assertThat(av.isReserved()).isTrue();
    }

    @Test
    void check_disabledFederation_nonReservedIsAvailable() {
        UsernameAvailability av = gateDisabled().check("magus").block();
        assertThat(av.available()).isTrue();
    }

    @Test
    void resolve_confusableCollision_autoDisambiguates() {
        // 'alice' collides (confusable) → gate tries alice2 (free) and returns it.
        StepVerifier.create(gateWithTaken(Set.of("alice")).resolve("alice"))
                .expectNext("alice2")
                .verifyComplete();
    }

    @Test
    void resolve_multipleCollisions_walksToFirstFree() {
        // alice, alice2, alice3 all taken → alice4 is the first free variant.
        StepVerifier.create(gateWithTaken(Set.of("alice", "alice2", "alice3")).resolve("alice"))
                .expectNext("alice4")
                .verifyComplete();
    }

    @Test
    void resolve_blankCandidate_errors() {
        StepVerifier.create(gateWithTaken(Set.of()).resolve("  "))
                .expectErrorSatisfies(e ->
                        assertThat(((UsernameGateException) e).reason()).isEqualTo("invalid"))
                .verify();
    }

    @Test
    void resolve_exhaustsBudget_errors() {
        // Every variant up to the budget is taken → the gate gives up (exhausted).
        Set<String> all = Set.of("z", "z2", "z3", "z4", "z5", "z6", "z7", "z8", "z9", "z10", "z11");
        StepVerifier.create(gateWithTaken(all).resolve("z"))
                .expectErrorSatisfies(e ->
                        assertThat(((UsernameGateException) e).reason()).isEqualTo("exhausted"))
                .verify();
    }
}

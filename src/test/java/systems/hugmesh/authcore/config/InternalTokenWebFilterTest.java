package systems.hugmesh.authcore.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@link InternalTokenWebFilter} fail-closed contract — the app-layer second factor on the
 * privilege-bearing {@code /bff/internal/**} surface. When ARMED (a token is configured) a
 * missing/wrong token is a 401 and the chain is NOT invoked; the correct token passes through.
 * When UNSET (dev/test/CI default) the filter is a pure no-op — matching the federation
 * outbound "blank token => do not enforce the header" semantics.
 */
class InternalTokenWebFilterTest {

    private static final String INTERNAL = "/bff/internal/desktop/sudo/entitlement?subject=alice&deviceId=d1";

    /** A chain that records whether it was reached (i.e. the request was allowed through). */
    private static final class RecordingChain implements WebFilterChain {
        final AtomicBoolean reached = new AtomicBoolean(false);
        @Override public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange) {
            reached.set(true);
            return Mono.empty();
        }
    }

    // ── ARMED (token configured) — fail-closed ───────────────────────────────────

    @Test
    void armed_missingToken_is401_andChainNotReached() {
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Internal-Token", "s3cret");
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get(INTERNAL));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(chain.reached).isFalse();   // never reached the controller
    }

    @Test
    void armed_wrongToken_is401_andChainNotReached() {
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Internal-Token", "s3cret");
        MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get(INTERNAL).header("X-Internal-Token", "WRONG"));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(chain.reached).isFalse();
    }

    @Test
    void armed_correctToken_passesThrough() {
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Internal-Token", "s3cret");
        MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get(INTERNAL).header("X-Internal-Token", "s3cret"));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.reached).isTrue();    // authorized -> reaches the controller
        assertThat(ex.getResponse().getStatusCode()).isNull();   // filter set no status
    }

    @Test
    void armed_customHeaderName_isHonoured() {
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Svc-Token", "s3cret");
        MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get(INTERNAL).header("X-Svc-Token", "s3cret"));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.reached).isTrue();
    }

    @Test
    void armed_nonInternalPath_isNotGated() {
        // the filter only guards /bff/internal/**; an admin path is untouched even when armed.
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Internal-Token", "s3cret");
        MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.get("/bff/admin/desktop/sudo"));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.reached).isTrue();
    }

    // ── UNSET (dev/test/CI default) — no-op ──────────────────────────────────────

    @Test
    void unset_isNoOp_internalPathPassesWithoutToken() {
        InternalTokenWebFilter filter = new InternalTokenWebFilter("X-Internal-Token", "");
        assertThat(filter.enforcing()).isFalse();
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get(INTERNAL));
        RecordingChain chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.reached).isTrue();    // no token configured -> no enforcement (clean boot)
        assertThat(ex.getResponse().getStatusCode()).isNull();
    }
}

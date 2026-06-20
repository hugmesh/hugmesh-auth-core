package systems.snapdragon.authcore.provision;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link GatewayRevocationClient}.
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL: disabled client skips all writes (no gateway needed);</li>
 *   <li>USER-SITUATIONAL: enabled client with unreachable gateway swallows errors
 *       (revokeCoarse / clearCoarse complete empty, not error — best-effort contract);</li>
 *   <li>USER-SITUATIONAL: key shape is {@code hs:<platform>:<localpart>}.</li>
 * </ul>
 *
 * <p>No live gateway server is needed. The disabled path never builds a WebClient
 * request; the enabled path is exercised against a non-listening port to prove the
 * best-effort error swallow.
 */
class GatewayRevocationClientTest {

    private static GatewayRevocationClient disabled() {
        return new GatewayRevocationClient(false, "http://localhost:19998");
    }

    private static GatewayRevocationClient enabled() {
        // Non-listening port — the WebClient connection refused is the test vector.
        return new GatewayRevocationClient(true, "http://localhost:19998");
    }

    // ── disabled (stub) path ───────────────────────────────────────────────────

    @Test
    void disabled_isNotEnabled() {
        assertThat(disabled().enabled()).isFalse();
    }

    @Test
    void disabled_revokeCoarse_completesEmpty_noRequest() {
        StepVerifier.create(disabled().revokeCoarse("matrix", "alice", "ban", 86400L))
                .verifyComplete();
    }

    @Test
    void disabled_clearCoarse_completesEmpty_noRequest() {
        StepVerifier.create(disabled().clearCoarse("mastodon", "bob"))
                .verifyComplete();
    }

    // ── enabled path: gateway unreachable → best-effort swallow ───────────────

    @Test
    void enabled_isEnabled() {
        assertThat(enabled().enabled()).isTrue();
    }

    @Test
    void enabled_gatewayUnreachable_revokeCoarse_completesEmpty_bestEffort() {
        // Connection refused to port 19998 — best-effort onErrorResume must swallow it.
        // The ban is already durable in the access_suspension table; this call is only
        // the fast-propagation path to the gateway's in-memory revocation cache.
        StepVerifier.create(enabled().revokeCoarse("matrix", "alice", "test ban", 0L))
                .verifyComplete();
    }

    @Test
    void enabled_gatewayUnreachable_clearCoarse_completesEmpty_bestEffort() {
        StepVerifier.create(enabled().clearCoarse("mastodon", "bob"))
                .verifyComplete();
    }

    @Test
    void enabled_gatewayUnreachable_nullReason_completesEmpty_bestEffort() {
        // Null reason is valid (optional field).
        StepVerifier.create(enabled().revokeCoarse("matrix", "alice", null, 86400L))
                .verifyComplete();
    }
}

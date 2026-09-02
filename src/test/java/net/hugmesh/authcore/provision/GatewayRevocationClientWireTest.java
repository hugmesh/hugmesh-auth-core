package net.hugmesh.authcore.provision;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Wire-level tests for {@link GatewayRevocationClient} against a REAL listening HTTP
 * server (JDK {@code com.sun.net.httpserver}) standing in for the gateway's
 * {@code GatewayRevocationController} — the "realistic gateway" coverage issue #7 asks
 * for. {@link GatewayRevocationClientTest} only proves the connection-refused swallow;
 * nothing there can distinguish "no request was made" from "a request died on a dead
 * port", nor prove the enabled branch serializes the contract body at all (a
 * connection-refused error fires before body encoding runs).
 *
 * <p>Delineated:
 * <ul>
 *   <li>INERT-TOGGLE PROOF: a disabled client pointed at a LIVE gateway delivers
 *       ZERO requests — the flag genuinely short-circuits the wire, not just the
 *       error handling;</li>
 *   <li>ENABLED CONTRACT: POST {@code /api/gateway/revocations} carries the JSON
 *       body ({@code key}, optional {@code reason}, {@code ttlSeconds} with the
 *       30-day default substituted for non-positive values); DELETE targets
 *       {@code /api/gateway/revocations/<key>};</li>
 *   <li>BEST-EFFORT: a 5xx response from a live gateway is swallowed (the request
 *       demonstrably reached the server, and the error still does not propagate).</li>
 * </ul>
 */
class GatewayRevocationClientWireTest {

    /** One received request: method, URI path, decoded body. */
    private record Received(String method, String path, String body) { }

    private static HttpServer server;
    private static String baseUrl;
    private static final List<Received> received = new CopyOnWriteArrayList<>();
    /** HTTP status the stub serves; reset to 204 before each test. */
    private static final AtomicInteger responseStatus = new AtomicInteger(204);

    @BeforeAll
    static void startGateway() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/gateway/revocations", exchange -> {
            String body;
            try (InputStream in = exchange.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            received.add(new Received(exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(), body));
            exchange.sendResponseHeaders(responseStatus.get(), -1);
            exchange.close();
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopGateway() {
        server.stop(0);
    }

    @BeforeEach
    void reset() {
        received.clear();
        responseStatus.set(204);
    }

    private static GatewayRevocationClient enabledClient() {
        return new GatewayRevocationClient(true, baseUrl);
    }

    private static GatewayRevocationClient disabledClient() {
        return new GatewayRevocationClient(false, baseUrl);
    }

    // ── inert-toggle proof: disabled + LIVE gateway = zero wire traffic ───────

    @Test
    void disabled_againstLiveGateway_sendsNothing() {
        GatewayRevocationClient client = disabledClient();
        StepVerifier.create(client.revokeCoarse("matrix", "alice", "ban", 86400L))
                .verifyComplete();
        StepVerifier.create(client.revokeSubject("alice", "role-revoke", 3600L))
                .verifyComplete();
        StepVerifier.create(client.clearCoarse("matrix", "alice"))
                .verifyComplete();
        assertThat(received)
                .as("broker.gateway-revocation.enabled=false must short-circuit "
                        + "BEFORE the wire — a live gateway sees no request at all")
                .isEmpty();
    }

    // ── enabled: POST contract ────────────────────────────────────────────────

    @Test
    void enabled_revokeCoarse_postsKeyReasonAndTtl() {
        StepVerifier.create(enabledClient().revokeCoarse("matrix", "alice", "ban", 86400L))
                .verifyComplete();
        assertThat(received).hasSize(1);
        Received r = received.get(0);
        assertThat(r.method()).isEqualTo("POST");
        assertThat(r.path()).isEqualTo("/api/gateway/revocations");
        assertThat(r.body())
                .contains("\"key\":\"hs:matrix:alice\"")
                .contains("\"reason\":\"ban\"")
                .contains("\"ttlSeconds\":86400");
    }

    @Test
    void enabled_revokeCoarse_nonPositiveTtl_sends30DayDefault() {
        StepVerifier.create(enabledClient().revokeCoarse("mastodon", "bob", "ban", 0L))
                .verifyComplete();
        assertThat(received).hasSize(1);
        assertThat(received.get(0).body())
                .contains("\"key\":\"hs:mastodon:bob\"")
                .contains("\"ttlSeconds\":2592000");
    }

    @Test
    void enabled_revokeCoarse_nullReason_omitsReasonField() {
        StepVerifier.create(enabledClient().revokeCoarse("matrix", "carol", null, 86400L))
                .verifyComplete();
        assertThat(received).hasSize(1);
        assertThat(received.get(0).body())
                .contains("\"key\":\"hs:matrix:carol\"")
                .doesNotContain("\"reason\"");
    }

    @Test
    void enabled_revokeSubject_postsSubjectKey() {
        StepVerifier.create(enabledClient().revokeSubject("alice", "role-revoke", 3600L))
                .verifyComplete();
        assertThat(received).hasSize(1);
        Received r = received.get(0);
        assertThat(r.method()).isEqualTo("POST");
        assertThat(r.path()).isEqualTo("/api/gateway/revocations");
        assertThat(r.body())
                .contains("\"key\":\"subject:alice\"")
                .contains("\"reason\":\"role-revoke\"")
                .contains("\"ttlSeconds\":3600");
    }

    // ── enabled: DELETE contract ──────────────────────────────────────────────

    @Test
    void enabled_clearCoarse_deletesKeyPath() {
        StepVerifier.create(enabledClient().clearCoarse("mastodon", "bob"))
                .verifyComplete();
        assertThat(received).hasSize(1);
        Received r = received.get(0);
        assertThat(r.method()).isEqualTo("DELETE");
        assertThat(r.path()).isEqualTo("/api/gateway/revocations/hs:mastodon:bob");
    }

    // ── enabled: best-effort swallow of a live server error ───────────────────

    @Test
    void enabled_serverError_requestReachesGateway_errorSwallowed() {
        responseStatus.set(500);
        StepVerifier.create(enabledClient().revokeCoarse("matrix", "alice", "ban", 86400L))
                .verifyComplete();
        assertThat(received)
                .as("the request must have reached the gateway — the swallow is of the "
                        + "RESPONSE error, not an unsent request")
                .hasSize(1);
    }

    @Test
    void enabled_serverError_clearCoarse_errorSwallowed() {
        responseStatus.set(503);
        StepVerifier.create(enabledClient().clearCoarse("matrix", "alice"))
                .verifyComplete();
        assertThat(received).hasSize(1);
    }
}

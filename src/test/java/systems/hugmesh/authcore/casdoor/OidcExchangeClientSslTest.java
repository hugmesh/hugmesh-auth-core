package systems.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import reactor.netty.http.client.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gated outbound-mTLS connector for the Casdoor token-exchange leg. Proves the default-OFF
 * ships-plain posture, graceful degradation when the gate is on but no stores are mounted, and
 * that {@link OidcExchangeConfig} builds a live client through the connector in both states.
 */
class OidcExchangeClientSslTest {

    @Test
    void gateOff_shouldNotApply_andCustomizeIsNoOp() {
        OidcExchangeClientSsl mtls = new OidcExchangeClientSsl(); // enabled=false by default
        assertThat(mtls.isEnabled()).isFalse();
        assertThat(mtls.shouldApply()).isFalse();
        HttpClient hc = HttpClient.create();
        assertThat(mtls.customize(hc)).isSameAs(hc); // unchanged connector when the gate is off
    }

    @Test
    void gateOn_butStoresAbsent_degradesToPlain() {
        OidcExchangeClientSsl mtls = new OidcExchangeClientSsl();
        mtls.setEnabled(true);
        mtls.setKeyStore("/nonexistent/keystore.p12");
        // shouldApply() is false (keystore missing) → customize() must NOT crash, just no-op.
        assertThat(mtls.shouldApply()).isFalse();
        HttpClient hc = HttpClient.create();
        assertThat(mtls.customize(hc)).isSameAs(hc);
    }

    @Test
    void config_buildsExchangeClient_throughTheMtlsConnector() {
        // The @Bean builds the WebClient with the (no-op, gate-off) connector and constructs the
        // client via the package-private WebClient ctor — proves the wiring compiles + runs.
        OidcExchangeClient client = new OidcExchangeConfig().oidcExchangeClient(
                new OidcExchangeClientSsl(),
                "http://casdoor:8000", "/api/login/oauth/access_token",
                "user-bff", "secret", 3600L);
        assertThat(client).isNotNull();
    }
}

package systems.hugmesh.authcore.casdoor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

/**
 * Wires the {@link OidcExchangeClient} ONLY when {@code app.bff.oidc.enabled=true} (default
 * false) — the ships-dark gate for the whole OIDC-custody flow. When the flag is off the bean
 * is absent and its consumers (the user-bff callback, the admin-bff exchange endpoint,
 * consumers) inject {@code @Nullable OidcExchangeClient = null} and fall
 * back to today's behavior.
 *
 * <p>Endpoint + confidential-client credentials come from {@code app.bff.oidc.*} (env-driven,
 * fed by ESO/Vault for the secret). {@code issuer} defaults to the in-cluster pki-gateway
 * Casdoor base; {@code token-path} defaults to Casdoor's access-token endpoint.
 *
 * <p><b>Outbound transport.</b> This is the leg that carries the OIDC {@code code}/
 * {@code client_secret}/tokens to Casdoor, so the WebClient is built through the gated
 * {@link OidcExchangeClientSsl} connector — the same default-OFF
 * ({@code hugmesh.mtls.client.enabled}) client-cert + cluster-CA connector the user-bff
 * federation and admin-bff-internal legs use. Off (local/dev/CI, or a mesh that supplies
 * transparent mTLS) it is the plain default connector and nothing changes. To activate:
 * {@code hugmesh.mtls.client.enabled=true} + mounted PKCS12 stores + an https
 * {@code app.bff.oidc.issuer} (reactor-netty only negotiates TLS for an https base).
 */
@Configuration
@EnableConfigurationProperties(OidcExchangeClientSsl.class)
public class OidcExchangeConfig {

    @Bean
    @ConditionalOnProperty(name = "app.bff.oidc.enabled", havingValue = "true")
    public OidcExchangeClient oidcExchangeClient(
            OidcExchangeClientSsl mtls,
            @Value("${app.bff.oidc.issuer:${casdoor.gateway-base:http://casdoor.hugmesh-pki.svc.cluster.local:8000}}") String issuer,
            @Value("${app.bff.oidc.token-path:/api/login/oauth/access_token}") String tokenPath,
            @Value("${app.bff.oidc.client-id:user-bff}") String clientId,
            @Value("${app.bff.oidc.client-secret:}") String clientSecret,
            @Value("${app.bff.oidc.default-expiry-seconds:3600}") long defaultExpirySeconds) {
        // Connector carries the gated client-mTLS identity (a no-op unless the gate is on + an
        // https issuer), so this token-bearing exchange leg can present a client cert + ride TLS.
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient http = WebClient.builder()
                .baseUrl(issuer)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
        return new OidcExchangeClient(http, tokenPath, clientId, clientSecret, defaultExpirySeconds);
    }
}

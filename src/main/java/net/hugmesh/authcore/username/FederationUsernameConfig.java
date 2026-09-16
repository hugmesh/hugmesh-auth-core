package net.hugmesh.authcore.username;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import net.hugmesh.authcore.casdoor.CasdoorServiceTokenClient;
import net.hugmesh.authcore.casdoor.OidcExchangeClientSsl;

import java.util.function.Supplier;

/**
 * Wires the {@link FederationUsernameClient} the {@link UsernameGate} consumes —
 * the reactive client over the federation registry's INTERNAL username
 * availability endpoint.
 *
 * <p>Mirrors {@code HomeserverAdminConfig} / {@code CasdoorAdminConfig}: the
 * client is ALWAYS present (so {@link UsernameGate} injects it non-null) but
 * gated by {@code federation.username-gate.enabled} (default false). With the
 * gate OFF the client never calls federation and the local {@code ReservedNames}
 * fast-path is the only check (so a federation-less dev/test/CI run boots clean);
 * the in-cluster deployment flips {@code FEDERATION_USERNAME_GATE_ENABLED=true}
 * once the three things below are in place — config-only, no code change.
 *
 * <h3>What an ENABLED gate needs, and why</h3>
 * <ol>
 *   <li><b>A ROLE_SERVICE bearer.</b> federation-api authenticates
 *       {@code /api/federation/username/**} ONLY as an OAuth2 resource server; it has no
 *       {@code X-Internal-Token} filter, so the legacy header alone gets a 401 and the client
 *       fails every check closed. The bearer is minted by
 *       {@link CasdoorServiceTokenClient} (client-credentials) from
 *       {@code federation.username-gate.service-bearer.{casdoor-base-url,client-id,client-secret}},
 *       each defaulting to the platform-wide
 *       {@code app.casdoor.platform.{base-url,client-id,client-secret}} every other internal
 *       ROLE_SERVICE caller in the org already uses — so a consumer that already carries those
 *       needs nothing new. All three must be non-blank for the bearer to be wired; otherwise the
 *       client is built header-only and, if the gate is ON, this config WARNs at boot.</li>
 *   <li><b>Outbound mTLS when the peer is {@code https://} with client-auth=need</b> (the
 *       in-cluster federation-api). Reuses the jar's gated
 *       {@link OidcExchangeClientSsl} connector ({@code hugmesh.mtls.client.*}, default OFF, the
 *       SAME gate + store paths the user-bff federation leg uses); off, the auto-configured
 *       connector is kept unchanged.</li>
 *   <li>The Casdoor application named by {@code client-id} must be a member of the
 *       {@code service} role (Casdoor-side seeding) or the minted JWT carries no
 *       {@code ROLE_SERVICE} and federation answers 403 — which this client also fails closed.</li>
 * </ol>
 *
 * <p>{@code base-url} defaults to the in-cluster federation service.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OidcExchangeClientSsl.class)
public class FederationUsernameConfig {

    private static final Logger log = LoggerFactory.getLogger(FederationUsernameConfig.class);

    @Bean
    FederationUsernameClient federationUsernameClient(
            WebClient.Builder builder,
            OidcExchangeClientSsl mtls,
            @Value("${federation.username-gate.enabled:false}") boolean enabled,
            @Value("${federation.username-gate.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${federation.username-gate.internal-token-header:X-Internal-Token}")
            String internalTokenHeader,
            @Value("${federation.username-gate.internal-token:}") String internalToken,
            @Value("${federation.username-gate.service-bearer.casdoor-base-url:${app.casdoor.platform.base-url:}}")
            String casdoorBaseUrl,
            @Value("${federation.username-gate.service-bearer.client-id:${app.casdoor.platform.client-id:}}")
            String clientId,
            @Value("${federation.username-gate.service-bearer.client-secret:${app.casdoor.platform.client-secret:}}")
            String clientSecret) {
        WebClient.Builder outbound = builder.clone();
        if (mtls.shouldApply()) {
            // Gate ON + identity keystore present: present this service's client cert and trust
            // the cluster CA on every hop this config builds (reactor-netty only negotiates TLS
            // for an https base, so a plain-http Casdoor base stays plain).
            HttpClient httpClient = mtls.customize(HttpClient.create());
            outbound.clientConnector(new ReactorClientHttpConnector(httpClient));
        }
        Supplier<Mono<String>> bearer = serviceBearer(outbound, casdoorBaseUrl, clientId, clientSecret);
        if (enabled && bearer == null) {
            log.warn("[username-gate] ENABLED but NO service-bearer credentials are configured "
                    + "(federation.username-gate.service-bearer.* / app.casdoor.platform.* — "
                    + "casdoor-base-url set={}, client-id set={}, client-secret set={}). "
                    + "federation-api accepts ONLY a ROLE_SERVICE bearer on "
                    + "/api/federation/username/**, so EVERY availability check will fail CLOSED "
                    + "and no provider-derived username can be minted until they are supplied.",
                    !isBlank(casdoorBaseUrl), !isBlank(clientId), !isBlank(clientSecret));
        }
        return new FederationUsernameClient(
                outbound.clone().baseUrl(baseUrl).build(),
                enabled, internalTokenHeader, internalToken, bearer);
    }

    /**
     * The client-credentials bearer supplier, or {@code null} when any of the three credentials
     * is blank (header-only legacy wiring). Package-private for the config test.
     */
    static Supplier<Mono<String>> serviceBearer(WebClient.Builder outbound, String casdoorBaseUrl,
                                                String clientId, String clientSecret) {
        if (isBlank(casdoorBaseUrl) || isBlank(clientId) || isBlank(clientSecret)) {
            return null;
        }
        return new CasdoorServiceTokenClient(
                outbound.clone().baseUrl(casdoorBaseUrl).build(), clientId, clientSecret);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}

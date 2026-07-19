package systems.hugmesh.authcore.username;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

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
 * once the federation availability endpoint is live — config-only, no code
 * change.
 *
 * <p>{@code base-url} defaults to the in-cluster federation service. The endpoint
 * is internal/ROLE_SERVICE, so an {@code X-Internal-Token} header carries the
 * shared service credential (env-injected; never in git).
 */
@Configuration(proxyBeanMethods = false)
public class FederationUsernameConfig {

    @Bean
    FederationUsernameClient federationUsernameClient(
            WebClient.Builder builder,
            @Value("${federation.username-gate.enabled:false}") boolean enabled,
            @Value("${federation.username-gate.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${federation.username-gate.internal-token-header:X-Internal-Token}")
            String internalTokenHeader,
            @Value("${federation.username-gate.internal-token:}") String internalToken) {
        return new FederationUsernameClient(
                builder.clone().baseUrl(baseUrl).build(),
                enabled, internalTokenHeader, internalToken);
    }
}

package systems.snapdragon.authcore.casdoor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link OidcExchangeClient} ONLY when {@code app.bff.oidc.enabled=true} (default
 * false) — the ships-dark gate for the whole OIDC-custody flow. When the flag is off the bean
 * is absent and its consumers (the user-bff callback, the admin-bff exchange endpoint,
 * {@link RawJwtRefreshService}) inject {@code @Nullable OidcExchangeClient = null} and fall
 * back to today's behavior.
 *
 * <p>Endpoint + confidential-client credentials come from {@code app.bff.oidc.*} (env-driven,
 * fed by ESO/Vault for the secret). {@code issuer} defaults to the in-cluster pki-gateway
 * Casdoor base; {@code token-path} defaults to Casdoor's access-token endpoint.
 */
@Configuration
public class OidcExchangeConfig {

    @Bean
    @ConditionalOnProperty(name = "app.bff.oidc.enabled", havingValue = "true")
    public OidcExchangeClient oidcExchangeClient(
            @Value("${app.bff.oidc.issuer:${casdoor.gateway-base:http://casdoor.snapdragon-pki.svc.cluster.local:8000}}") String issuer,
            @Value("${app.bff.oidc.token-path:/api/login/oauth/access_token}") String tokenPath,
            @Value("${app.bff.oidc.client-id:user-bff}") String clientId,
            @Value("${app.bff.oidc.client-secret:}") String clientSecret,
            @Value("${app.bff.oidc.default-expiry-seconds:3600}") long defaultExpirySeconds) {
        return new OidcExchangeClient(issuer, tokenPath, clientId, clientSecret, defaultExpirySeconds);
    }
}

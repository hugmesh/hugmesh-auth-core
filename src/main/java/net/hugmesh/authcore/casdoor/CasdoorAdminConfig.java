package net.hugmesh.authcore.casdoor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.authcore.username.UsernameGate;

/**
 * Wires the real Casdoor admin write client. Gated behind
 * {@code casdoor.admin.enabled} (default false) so unit tests and a Casdoor-less
 * dev run boot clean — when the bean is absent its caller
 * ({@code AdminController}) injects {@code @Nullable CasdoorAdminClient = null}
 * and skips the Casdoor write (the durable allowlist row is still written).
 *
 * <p>Endpoint + credentials come from {@code casdoor.admin.*} (env-driven, same
 * shape as hugmesh-actions). {@code base-url} defaults to the pki-gateway base
 * ({@code casdoor.gateway-base}); a deployment may point it straight at the
 * Casdoor admin URL.
 */
@Configuration
public class CasdoorAdminConfig {

    @Bean
    @ConditionalOnProperty(name = "casdoor.admin.enabled", havingValue = "true")
    public CasdoorAdminClient casdoorAdminClient(
            @Value("${casdoor.admin.base-url:${casdoor.gateway-base:http://casdoor.hugmesh-pki.svc.cluster.local:8000}}") String baseUrl,
            @Value("${casdoor.admin.client-id:admin-bff}") String clientId,
            @Value("${casdoor.admin.client-secret:}") String clientSecret,
            @Value("${casdoor.admin.organization:${casdoor.organization:hugmesh}}") String organization,
            @Value("${casdoor.admin.signup-application:app-admin-bff}") String signupApplication,
            UsernameGate usernameGate) {
        // The username-derivation gate is wired into the write client so the
        // SERVICE layer rejects/disambiguates a reserved/confusable derived
        // username before any add-user / enable write.
        return new CasdoorAdminClient(baseUrl, clientId, clientSecret, organization,
                signupApplication, usernameGate);
    }
}

package net.hugmesh.authcore.casdoor;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * Wires the A4 MFA-challenge collaborators. The {@link MfaFactorVerifier} default is
 * FAIL-CLOSED: with no real Casdoor verification wired (the deployed-shape-specific
 * verify endpoints are validated against casdoor-all-in-one, like the
 * {@link CasdoorAdminClient} payloads), the default verifier verifies NOTHING — so the
 * whole challenge leg is inert until a real verifier bean replaces it. This keeps the
 * ships-dark posture safe even if {@code app.casdoor.mfa.enabled} is flipped before the
 * real verifier lands: no factor can be "verified" by accident.
 *
 * <p>{@link ConditionalOnMissingBean} so a deployment (or test) supplying a real
 * {@link MfaFactorVerifier} bean takes precedence.
 */
@Configuration
public class MfaChallengeConfig {

    /** Fail-closed default verifier — verifies NOTHING (returns {@code false} for every
     *  factor) until a real Casdoor-backed verifier bean is wired. */
    @Bean
    @ConditionalOnMissingBean(MfaFactorVerifier.class)
    public MfaFactorVerifier denyAllMfaFactorVerifier() {
        return (subject, username, factor, credential) -> Mono.just(false);
    }
}

package net.hugmesh.authcore.mfa;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link MfaPreconditionBootGuard} against a REAL Spring context refresh, not a direct method call.
 * {@link MfaPreconditionBootGuardTest} covers the decision logic; this class covers the thing that
 * actually decides whether a pod comes up: whether {@code refresh()} completes.
 *
 * <p>{@link #realContextStillRefreshes_whenMfaIsOnAndTheFactorKeyIsAbsent()} is the important one:
 * MFA armed with the factor key resolving empty. In-cluster the ESO {@code secretKeyRef} is
 * REQUIRED since the 2.4.2 release chain (a fully absent Secret is a scheduler-level
 * {@code CreateContainerConfigError} before this code runs), but the state stays reachable — a
 * Secret present with a blank value, compose/bare-metal, a pre-tightening manifest — and it MUST
 * refresh, because admin-bff-api is the admin/superadmin control plane: a throw here is a
 * CrashLoopBackOff of the plane an operator would use to fix the very thing being reported.
 */
class MfaPreconditionBootGuardContextTest {

    /** A 32-byte base64 key shaped like the real ESO/Vault value (test-only, not a secret). */
    private static final String KEY_32B = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /** The committed cluster profile set (specs/cluster/manifests/admin-bff-api). */
    private static final String[] CLUSTER_PROFILES = {"casdoor", "clickhouse"};

    /**
     * A context registering the REAL annotated classes, so {@code @Profile}, {@code @Value} and the
     * {@code @Autowired} constructor all genuinely apply — without dragging in the R2DBC-dependent
     * beans of the same package.
     */
    private static AnnotationConfigApplicationContext ctx(Map<String, Object> props,
                                                          String... profiles) {
        AnnotationConfigApplicationContext c = new AnnotationConfigApplicationContext();
        if (profiles.length > 0) {
            c.getEnvironment().setActiveProfiles(profiles);
        }
        c.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test-props", new HashMap<>(props)));
        c.register(MfaSecretCipher.class, RecoveryCodeService.class,
                MfaPreconditionBootGuard.class);
        return c;
    }

    @Test
    @DisplayName("MFA off + nothing configured — refreshes, and the bean really is wired")
    void realContextRefreshes_whenMfaOffAndNothingConfigured() {
        try (AnnotationConfigApplicationContext c = ctx(Map.of())) {
            assertThatCode(c::refresh).doesNotThrowAnyException();
            assertThat(c.getBean(MfaPreconditionBootGuard.class)).isNotNull();
        }
    }

    @Test
    @DisplayName("THE CRASH-LOOP REGRESSION: MFA on, no factor key, cluster profiles — REFRESHES")
    void realContextStillRefreshes_whenMfaIsOnAndTheFactorKeyIsAbsent() {
        // admin-bff-api with MFA armed and APP_MFA_FACTOR_KEY resolving to empty (a blank
        // Secret value, compose, or a pre-tightening manifest; the required in-cluster ref
        // makes full ABSENCE a scheduler-level failure since the 2.4.2 release chain).
        try (AnnotationConfigApplicationContext c = ctx(Map.of(
                "app.casdoor.mfa.enabled", "true",
                "app.mfa.webauthn.rp-id", "admin.hugmesh.net",
                "app.mfa.webauthn.origins", "https://admin.hugmesh.net"),
                CLUSTER_PROFILES)) {
            assertThatCode(c::refresh).doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("MFA on with NOTHING configured at all, cluster profiles — still REFRESHES")
    void realContextStillRefreshes_whenMfaIsOnAndNothingElseIsConfigured() {
        try (AnnotationConfigApplicationContext c =
                     ctx(Map.of("app.casdoor.mfa.enabled", "true"), CLUSTER_PROFILES)) {
            assertThatCode(c::refresh).doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("the opt-in property aborts refresh")
    void realContextREFUSESToRefresh_whenTheOptInIsSet() {
        try (AnnotationConfigApplicationContext c = ctx(Map.of(
                "app.casdoor.mfa.enabled", "true",
                "app.mfa.preconditions.fail-fast", "true",
                "app.mfa.webauthn.rp-id", "admin.hugmesh.net",
                "app.mfa.webauthn.origins", "https://admin.hugmesh.net"),
                CLUSTER_PROFILES)) {
            assertThatThrownBy(c::refresh)
                    .hasStackTraceContaining("REFUSING TO BOOT")
                    .hasStackTraceContaining("app.mfa.factor-key");
        }
    }

    @Test
    @DisplayName("the opt-in works via the ENV VAR spelling the WARN tells operators to set")
    void theOptInBindsFromItsEnvironmentVariableName() {
        // The WARN and the README both tell an operator to set APP_MFA_PRECONDITIONS_FAIL_FAST.
        // Spring's SystemEnvironmentPropertySource is what maps that to the dotted property, so
        // this proves the advice is actually actionable rather than merely plausible.
        AnnotationConfigApplicationContext c = ctx(Map.of("app.casdoor.mfa.enabled", "true"),
                CLUSTER_PROFILES);
        c.getEnvironment().getPropertySources().addFirst(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.of(MfaPreconditionBootGuard.ENV_FAIL_FAST, "true")));
        try (c) {
            assertThatThrownBy(c::refresh)
                    .hasStackTraceContaining("REFUSING TO BOOT")
                    .hasStackTraceContaining("app.mfa.preconditions.fail-fast=true");
        }
    }

    @Test
    @DisplayName("the compose dev stack refreshes even with the opt-in armed")
    void realContextRefreshes_onTheComposeDevPosture_evenWithTheOptInArmed() {
        // compose: SPRING_PROFILES_ACTIVE=casdoor,dev, MFA on, factor key provisioned, and NEITHER
        // WebAuthn property set. An operator who arms fail-fast fleet-wide must not break this.
        try (AnnotationConfigApplicationContext c = ctx(Map.of(
                "app.casdoor.mfa.enabled", "true",
                "app.mfa.preconditions.fail-fast", "true",
                "app.mfa.factor-key", KEY_32B), "casdoor", "dev")) {
            assertThatCode(c::refresh).doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("the bean is absent under the test profile, so consumer test suites never see it")
    void guardBeanIsAbsentUnderTestProfile() {
        try (AnnotationConfigApplicationContext c = ctx(Map.of(
                "app.casdoor.mfa.enabled", "true",
                "app.mfa.preconditions.fail-fast", "true"), "test")) {
            assertThatCode(c::refresh).doesNotThrowAnyException();
            assertThat(c.getBeanNamesForType(MfaPreconditionBootGuard.class)).isEmpty();
        }
    }
}

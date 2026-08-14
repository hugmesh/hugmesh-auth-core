package net.hugmesh.authcore.mfa;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.StandardEnvironment;
import net.hugmesh.authcore.config.InternalSurfaceBootGuard;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The {@link MfaPreconditionBootGuard} contract. The guard is driven by calling
 * {@code afterSingletonsInstantiated()} directly (that is exactly what Spring does during context
 * refresh, and a throw there aborts the boot) — no Spring context needed.
 *
 * <p>TWO properties matter most in this file, and they pull in opposite directions:
 * <ol>
 *   <li>{@link MfaOff#bootsFine_whenMfaDisabled_evenWithNothingConfigured()} — MFA off must never
 *       be able to acquire a new startup failure from this class.</li>
 *   <li>{@link DefaultIsWarnNotFail} — MFA ON with unmet preconditions must ALSO still start.
 *       That state is REACHABLE ({@code APP_CASDOOR_MFA_ENABLED: "true"} with an empty factor
 *       key: historically an absent {@code optional: true} Secret; since the 2.4.2 release chain
 *       the in-cluster ref is REQUIRED, so this arises from a present-but-empty Secret value,
 *       compose/bare-metal runs, or a pre-tightening manifest), and admin-bff-api — the only
 *       consumer that scans this package — is the admin control plane. Crashing it would be
 *       worse than the degradation it reports.</li>
 * </ol>
 * The hard failure is reachable only through the explicit
 * {@code app.mfa.preconditions.fail-fast} opt-in, covered by {@link FailFastOptIn}.
 */
class MfaPreconditionBootGuardTest {

    /** A 32-byte base64 key shaped like the real ESO/Vault value (test-only, not a secret). */
    private static final String KEY_32B = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /** Captures what the guard actually logs, so "it WARNs loudly" is a real assertion. */
    private ListAppender<ILoggingEvent> logs;
    private ch.qos.logback.classic.Logger guardLogger;

    @BeforeEach
    void attachLogAppender() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        guardLogger = ctx.getLogger(MfaPreconditionBootGuard.class);
        logs = new ListAppender<>();
        logs.setContext(ctx);
        logs.start();
        guardLogger.addAppender(logs);
    }

    @AfterEach
    void detachLogAppender() {
        guardLogger.detachAppender(logs);
        logs.stop();
    }

    private List<ILoggingEvent> warnings() {
        return logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
    }

    private String onlyWarning() {
        List<ILoggingEvent> warns = warnings();
        assertThat(warns).as("exactly one WARN expected").hasSize(1);
        return warns.get(0).getFormattedMessage();
    }

    /** The DEFAULT posture: {@code app.mfa.preconditions.fail-fast} unset/false. */
    private static MfaPreconditionBootGuard guard(boolean mfaEnabled, String factorKey,
                                                  String rpId, String origins, boolean dev) {
        return new MfaPreconditionBootGuard(mfaEnabled, false, rpId, origins,
                new MfaSecretCipher(factorKey), new RecoveryCodeService(factorKey), dev);
    }

    /** The OPT-IN posture: {@code app.mfa.preconditions.fail-fast=true}. */
    private static MfaPreconditionBootGuard strictGuard(boolean mfaEnabled, String factorKey,
                                                        String rpId, String origins, boolean dev) {
        return new MfaPreconditionBootGuard(mfaEnabled, true, rpId, origins,
                new MfaSecretCipher(factorKey), new RecoveryCodeService(factorKey), dev);
    }

    // ── the blast-radius guarantee ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("MFA OFF (the consumer default) — no new startup failure, and total silence")
    class MfaOff {

        @Test
        void bootsFine_whenMfaDisabled_evenWithNothingConfigured() {
            // mfa.enabled=false, no factor key, no rp-id, no origins, no dev profile. This MUST
            // boot AND stay quiet, or the guard becomes noise on every MFA-off deployment.
            MfaPreconditionBootGuard g = guard(false, "", "", "", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
            assertThat(warnings()).isEmpty();
        }

        @Test
        void bootsFine_whenMfaDisabled_withLocalhostRpIdOnNonDevProfile() {
            // The literal consumer default (application.yml rp-id: ${APP_MFA_WEBAUTHN_RP_ID:localhost})
            // on a prod profile — still fine, because MFA is off.
            MfaPreconditionBootGuard g =
                    guard(false, "", "localhost", "https://localhost", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
            assertThat(warnings()).isEmpty();
        }

        @Test
        void bootsFine_whenMfaDisabled_withNullPropertiesAndNullComponents() {
            // Defensive: a consumer context that somehow supplies nothing at all still boots
            // while MFA is dark (no NPE from the guard).
            MfaPreconditionBootGuard g =
                    new MfaPreconditionBootGuard(false, false, null, null, null, null, false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void bootsFine_whenMfaDisabled_evenWithTheFailFastOptInArmed() {
            // fail-fast is an escalation of an MFA problem, never a check of its own: with MFA off
            // there is nothing to escalate, so arming it fleet-wide is still safe.
            MfaPreconditionBootGuard g = new MfaPreconditionBootGuard(false, true, "", "",
                    new MfaSecretCipher(""), new RecoveryCodeService(""), false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }
    }

    // ── THE CRASH-LOOP REGRESSION GUARD: default is WARN, never a boot abort ──────────────

    @Nested
    @DisplayName("DEFAULT (no opt-in) — unmet preconditions WARN loudly and the app still starts")
    class DefaultIsWarnNotFail {

        @Test
        void startsAnyway_andWarns_inTheExactLiveClusterDegradedState() {
            // specs/cluster/manifests/admin-bff-api/deployment.yaml: APP_CASDOOR_MFA_ENABLED=true,
            // RP_ID/ORIGINS set to the real admin host, profiles casdoor,clickhouse (NOT dev), and
            // APP_MFA_FACTOR_KEY resolving EMPTY. The in-cluster ref is REQUIRED since the 2.4.2
            // release chain (an absent Secret is the scheduler's problem now), but an empty key
            // still arrives via a present-but-blank Secret value or a pre-tightening manifest —
            // and the pod must keep booting through it.
            MfaPreconditionBootGuard g = guard(true, "", "admin.hugmesh.net",
                    "https://admin.hugmesh.net", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();

            String warn = onlyWarning();
            assertThat(warn)
                    .contains(MfaPreconditionBootGuard.BANNER)
                    // the property AND the env var an operator actually sets
                    .contains("app.mfa.factor-key")
                    .contains("APP_MFA_FACTOR_KEY")
                    // ...the consequence, in both halves
                    .contains("503")
                    .contains("locked out")
                    // ...that it is NOT stopping the boot
                    .contains("STARTING ANYWAY")
                    // ...and how to make it stop the boot, if that is what you want
                    .contains("app.mfa.preconditions.fail-fast")
                    .contains("APP_MFA_PRECONDITIONS_FAIL_FAST")
                    .contains("app.casdoor.mfa.enabled=true");
        }

        @Test
        void startsAnyway_andWarns_whenTheRelyingPartyIsLoopbackOnANonDevProfile() {
            // compose runs MFA on with NEITHER webauthn property set; its `dev` profile is only the
            // ADMIN_BFF_PROFILES default, so ADMIN_BFF_PROFILES=casdoor reaches exactly this state.
            // It boots today, so it must keep booting.
            MfaPreconditionBootGuard g = guard(true, KEY_32B, "localhost", "https://localhost", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();

            assertThat(onlyWarning())
                    .contains("app.mfa.webauthn.rp-id")
                    .contains("APP_MFA_WEBAUTHN_RP_ID")
                    .contains("app.mfa.webauthn.origins")
                    .contains("STARTING ANYWAY")
                    // the factor key IS provisioned here, so it must not be blamed
                    .doesNotContain("app.mfa.factor-key");
        }

        @Test
        void oneWarnNamesEveryUnmetPrecondition_soNothingIsFixAndRediscover() {
            MfaPreconditionBootGuard g = guard(true, "", "", "", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();

            assertThat(onlyWarning())
                    .contains("app.mfa.factor-key")
                    .contains("app.mfa.webauthn.rp-id")
                    .contains("app.mfa.webauthn.origins")
                    .contains("3 of its preconditions");
        }

        @Test
        void staysQuiet_whenThePreconditionsAreActuallyMet() {
            MfaPreconditionBootGuard g = guard(true, KEY_32B, "admin.hugmesh.net",
                    "https://admin.hugmesh.net", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
            assertThat(warnings()).isEmpty();
        }
    }

    // ── HOLE 1: the recovery-code lockout, escalated by the opt-in ────────────────────────

    @Nested
    @DisplayName("OPT-IN app.mfa.preconditions.fail-fast=true — then, and only then, boot aborts")
    class FailFastOptIn {

        @Test
        void refusesToBoot_whenMfaOnAndFactorKeyMissing() {
            // rp-id/origins are dev-clean here so the ONLY problem is the factor key.
            MfaPreconditionBootGuard g = strictGuard(true, "", "", "", true);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("REFUSING TO BOOT")
                    // the property MUST be named
                    .hasMessageContaining("app.mfa.factor-key")
                    // ...and the env var an operator actually sets
                    .hasMessageContaining("APP_MFA_FACTOR_KEY")
                    // ...and WHY it is fatal
                    .hasMessageContaining("locked out")
                    .hasMessageContaining("app.casdoor.mfa.enabled=true")
                    // ...and WHAT made it fatal rather than a WARN, so it can be undone
                    .hasMessageContaining("app.mfa.preconditions.fail-fast=true")
                    .hasMessageContaining("APP_MFA_PRECONDITIONS_FAIL_FAST");
        }

        @Test
        void refusesToBoot_whenFactorKeyIsBlankWhitespace() {
            // "   " derives no key (MfaSecretCipher.deriveKey uses isBlank), so it must be
            // treated as absent, not as a passphrase.
            MfaPreconditionBootGuard g = strictGuard(true, "   ", "", "", true);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.factor-key");
        }

        @Test
        void boots_whenMfaOnAndFactorKeyPresent_devProfile() {
            // The compose dev stack: MFA on, factor key provisioned, no rp-id/origins, dev profile.
            MfaPreconditionBootGuard g = strictGuard(true, KEY_32B, "", "", true);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void boots_whenFactorKeyIsAPassphrase() {
            // MfaSecretCipher folds an arbitrary passphrase to 32 bytes via SHA-256, so
            // isAvailable() is true — the guard must agree with that component, not re-derive.
            MfaPreconditionBootGuard g =
                    strictGuard(true, "not-base64-just-a-passphrase", "", "", true);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        // ── HOLE 2: the WebAuthn RP-ID silent-localhost default ──────────────────────────

        @Test
        void refusesToBoot_whenRpIdIsStillLocalhostOnNonDevProfile() {
            MfaPreconditionBootGuard g =
                    strictGuard(true, KEY_32B, "localhost", "https://localhost", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("REFUSING TO BOOT")
                    .hasMessageContaining("app.mfa.webauthn.rp-id")
                    .hasMessageContaining("APP_MFA_WEBAUTHN_RP_ID")
                    .hasMessageContaining("loopback host");
        }

        @Test
        void refusesToBoot_whenRpIdIsAbsentOnNonDevProfile() {
            MfaPreconditionBootGuard g =
                    strictGuard(true, KEY_32B, "", "https://admin.hugmesh.net", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.webauthn.rp-id")
                    .hasMessageContaining("silently defaults to 'localhost'");
        }

        @Test
        void refusesToBoot_whenRpIdIsLoopbackIpOnNonDevProfile() {
            MfaPreconditionBootGuard g =
                    strictGuard(true, KEY_32B, "127.0.0.1", "https://127.0.0.1:8443", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.webauthn.rp-id");
        }

        @Test
        void refusesToBoot_whenOriginsAreStillLocalhostEvenWithARealRpId() {
            // A half-configured deploy: real RP ID, forgotten origin allowlist. The ceremony
            // would reject every real browser origin, so it is equally reportable.
            MfaPreconditionBootGuard g =
                    strictGuard(true, KEY_32B, "admin.hugmesh.net", "https://localhost", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.webauthn.origins")
                    .hasMessageContaining("APP_MFA_WEBAUTHN_ORIGINS")
                    // ...and NOT a spurious rp-id complaint
                    .hasMessageNotContaining("app.mfa.webauthn.rp-id");
        }

        @Test
        void boots_whenTheClusterPostureIsFullyConfigured() {
            // The exact committed cluster values (specs/cluster/manifests/admin-bff-api/
            // deployment.yaml: RP_ID=admin.hugmesh.net, ORIGINS=https://admin.hugmesh.net,
            // profiles casdoor,clickhouse => NOT dev) plus a provisioned key.
            MfaPreconditionBootGuard g = strictGuard(true, KEY_32B, "admin.hugmesh.net",
                    "https://admin.hugmesh.net", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void boots_whenOriginsMixLoopbackWithARealOrigin() {
            // Not ALL loopback -> a real browser origin can pass, so this is not a problem.
            MfaPreconditionBootGuard g = strictGuard(true, KEY_32B, "admin.hugmesh.net",
                    "https://localhost, https://admin.hugmesh.net", false);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void boots_onDevProfile_withNoRpIdAtAll() {
            // THE compose-stack regression guard, and specifically under the opt-in: an operator
            // who arms fail-fast fleet-wide must not thereby break their own local stack, where
            // loopback is the CORRECT Relying Party.
            MfaPreconditionBootGuard g = strictGuard(true, KEY_32B, "", "", true);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void boots_onDevProfile_withExplicitLocalhostRpId() {
            MfaPreconditionBootGuard g =
                    strictGuard(true, KEY_32B, "localhost", "https://localhost", true);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void reportsBothProblemsAtOnce_whenKeyAndRpIdAreBothMissing() {
            // An operator should not have to fix-and-rediscover: one boot, both properties named.
            MfaPreconditionBootGuard g =
                    strictGuard(true, "", "localhost", "https://localhost", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.factor-key")
                    .hasMessageContaining("app.mfa.webauthn.rp-id")
                    .hasMessageContaining("app.mfa.webauthn.origins");
        }

        @Test
        void theOptInEscalatesAndDoesNotAlsoLogTheStartingAnywayWarn() {
            // The two paths are exclusive: a fatal boot must not also claim it is starting anyway.
            MfaPreconditionBootGuard g = strictGuard(true, "", "admin.hugmesh.net",
                    "https://admin.hugmesh.net", false);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class);
            assertThat(warnings()).isEmpty();
        }
    }

    // ── the dev-detection rule itself ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("dev detection = a dev/test Spring profile is active (InternalSurfaceBootGuard's set)")
    class DevDetection {

        @Test
        void devProfilesAreRecognised() {
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"casdoor", "dev"})).isTrue();
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"test"})).isTrue();
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{" DEV "})).isTrue();
        }

        @Test
        void theDevSetIsExactlyInternalSurfaceBootGuardsProfileNames() {
            // config/InternalSurfaceBootGuard is @Profile("!dev & !test"). This guard's dev set
            // must be those two names and nothing else, so auth-core has ONE dev rule. In
            // particular `local` is NOT a dev profile: no manifest, compose service or
            // application-*.yml in this fleet ever activates one, so admitting it would have
            // widened the exemption for a profile that does not exist.
            //
            // Derived from the OTHER guard's actual @Profile annotation rather than compared to a
            // literal: a literal "dev, test" only pins THIS side, so InternalSurfaceBootGuard could
            // later gain or drop a profile and the two rules would silently disagree again — which
            // is exactly the overclaim an adversarial review already caught here once.
            String profileExpression = InternalSurfaceBootGuard.class.getAnnotation(Profile.class).value()[0];
            Set<String> internalSurfaceDevProfiles = Arrays.stream(profileExpression.split("&"))
                    .map(String::trim)
                    .filter(token -> token.startsWith("!"))
                    .map(token -> token.substring(1).trim())
                    .collect(Collectors.toCollection(TreeSet::new));

            assertThat(internalSurfaceDevProfiles)
                    .as("InternalSurfaceBootGuard's @Profile must stay a pure negated-AND of dev profiles; "
                            + "if it gained a positive term this derivation is no longer valid")
                    .isNotEmpty();

            Set<String> mfaGuardDevProfiles = Arrays.stream(MfaPreconditionBootGuard.DEV_PROFILE_LIST.split(","))
                    .map(String::trim)
                    .collect(Collectors.toCollection(TreeSet::new));

            assertThat(mfaGuardDevProfiles)
                    .as("auth-core must have ONE dev rule: this guard's dev set must equal the set "
                            + "InternalSurfaceBootGuard exempts via @Profile(\"%s\")", profileExpression)
                    .isEqualTo(internalSurfaceDevProfiles);

            // Every name the other guard exempts must actually be treated as dev-like here.
            for (String devProfile : internalSurfaceDevProfiles) {
                assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{devProfile}))
                        .as("profile '%s' is exempted by InternalSurfaceBootGuard but not dev-like here", devProfile)
                        .isTrue();
            }
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"local"})).isFalse();
        }

        @Test
        void deploymentProfilesAreNotDev() {
            // The committed cluster value.
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"casdoor", "clickhouse"}))
                    .isFalse();
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"routes"})).isFalse();
            // "development" must NOT match "dev" — exact token only.
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{"development"})).isFalse();
        }

        @Test
        void noProfilesIsNotDev() {
            // An unprofiled deployment gets the STRICT treatment (the safe direction for an RP ID).
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{})).isFalse();
            assertThat(MfaPreconditionBootGuard.isDevLike(null)).isFalse();
            assertThat(MfaPreconditionBootGuard.isDevLike(new String[]{null})).isFalse();
        }

        @Test
        void springCtorResolvesDevFromTheEnvironmentsActiveProfiles() {
            // Prove the wiring, not just the helper: the @Autowired ctor must read the profile
            // off the real Environment. dev + MFA on + key set + no rp-id => no problem at all,
            // proven by the opt-in being armed and the boot still succeeding.
            StandardEnvironment dev = new StandardEnvironment();
            dev.setActiveProfiles("casdoor", "dev");
            MfaPreconditionBootGuard g = new MfaPreconditionBootGuard(true, true, "", "",
                    new MfaSecretCipher(KEY_32B), new RecoveryCodeService(KEY_32B), dev);
            assertThatCode(g::afterSingletonsInstantiated).doesNotThrowAnyException();
        }

        @Test
        void springCtorTreatsAClusterProfileSetAsNonDev() {
            StandardEnvironment prod = new StandardEnvironment();
            prod.setActiveProfiles("casdoor", "clickhouse");
            MfaPreconditionBootGuard g = new MfaPreconditionBootGuard(true, true, "", "",
                    new MfaSecretCipher(KEY_32B), new RecoveryCodeService(KEY_32B), prod);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.webauthn.rp-id");
        }

        @Test
        void springCtorWithANullEnvironmentIsTreatedAsNonDev() {
            // DISCRIMINATING: rp-id/origins are UNSET and the opt-in is armed, so a null
            // Environment classified as dev would boot silently while non-dev must throw. (The
            // previous version of this test passed real cluster values, which boot under BOTH
            // branches — it could not observe the property in its name.)
            MfaPreconditionBootGuard g = new MfaPreconditionBootGuard(true, true, "", "",
                    new MfaSecretCipher(KEY_32B), new RecoveryCodeService(KEY_32B), null);
            assertThatThrownBy(g::afterSingletonsInstantiated)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.mfa.webauthn.rp-id");
        }
    }

    // ── the key-material invariant ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("the guard never holds the factor key, so no message can leak it")
    class NoKeyMaterial {

        /**
         * Asserts the STRUCTURAL invariant instead of the un-failable one it replaces. The old
         * {@code failureMessageNeverContainsTheKeyMaterial} asserted the message omits the key
         * string — but the guard's constructors take {@link MfaSecretCipher}/
         * {@link RecoveryCodeService}, never the key, so no implementation could ever have made it
         * fail. What actually keeps the key out of the logs is that the class cannot see it: it
         * asks the two components {@code isAvailable()}. This test fails the moment a refactor
         * binds {@code app.mfa.factor-key} into the guard itself — which is the only way the leak
         * could be reintroduced.
         */
        @Test
        void theAutowiredCtorBindsNoFactorKeyProperty() {
            Constructor<?> springCtor = null;
            for (Constructor<?> c : MfaPreconditionBootGuard.class.getDeclaredConstructors()) {
                if (c.isAnnotationPresent(Autowired.class)) {
                    springCtor = c;
                }
            }
            assertThat(springCtor).as("the @Autowired constructor").isNotNull();

            for (Annotation[] onParam : springCtor.getParameterAnnotations()) {
                for (Annotation a : onParam) {
                    if (a instanceof Value v) {
                        assertThat(v.value())
                                .as("no @Value on the guard may bind the factor key")
                                .doesNotContain(MfaPreconditionBootGuard.PROP_FACTOR_KEY);
                    }
                }
            }
        }

        @Test
        void noDeclaredFieldCanHoldTheKeyString() {
            // The only String state the guard keeps is the two non-secret WebAuthn properties.
            long stringFields = java.util.Arrays.stream(
                            MfaPreconditionBootGuard.class.getDeclaredFields())
                    .filter(f -> f.getType() == String.class)
                    .filter(f -> !java.lang.reflect.Modifier.isStatic(f.getModifiers()))
                    .count();
            assertThat(stringFields).as("rpId + originsCsv only").isEqualTo(2);
        }
    }

    // ── the loopback classifier ───────────────────────────────────────────────────────────

    @Nested
    @DisplayName("loopback host / origin classification")
    class LoopbackClassification {

        @Test
        void loopbackHostsAreRecognised() {
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("localhost")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("LOCALHOST")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("localhost.")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("127.0.0.1")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("::1")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("[::1]")).isTrue();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("0.0.0.0")).isTrue();
            // RFC 6761 reserves the whole .localhost tree.
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("admin.localhost")).isTrue();
        }

        @Test
        void realHostsAreNotLoopback() {
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("admin.hugmesh.net")).isFalse();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("hugmesh.net")).isFalse();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("10.0.0.5")).isFalse();
            // mDNS .local is DELIBERATELY not loopback: a LAN mesh node may legitimately be
            // named foo.local and must not be reported.
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("mesh-node.local")).isFalse();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost(null)).isFalse();
            assertThat(MfaPreconditionBootGuard.isLoopbackHost("")).isFalse();
        }

        @Test
        void allLoopbackOriginLists() {
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins("https://localhost")).isTrue();
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins("https://localhost:8443"))
                    .isTrue();
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins(
                    "http://localhost:4200, https://127.0.0.1")).isTrue();
            // blank / empty-entry lists yield no usable origin at all
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins("")).isTrue();
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins(null)).isTrue();
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins(" , ")).isTrue();
        }

        @Test
        void originListsContainingARealOriginAreNotAllLoopback() {
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins(
                    "https://admin.hugmesh.net")).isFalse();
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins(
                    "https://localhost,https://admin.hugmesh.net")).isFalse();
            // An unparseable/exotic entry must count as NON-loopback — never raise an alarm on a
            // value this classifier merely failed to understand.
            assertThat(MfaPreconditionBootGuard.isAllLoopbackOrigins("!!not a uri!!")).isFalse();
        }
    }
}

package systems.hugmesh.authcore.mfa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * STARTUP CHECK for the MFA preconditions that, if unmet, produce a silently-broken or
 * silently-UNRECOVERABLE deployment rather than an error. By DEFAULT it reports them as a loud,
 * actionable {@code WARN} and lets the application start; it aborts the boot ONLY when the
 * operator opts in via {@code app.mfa.preconditions.fail-fast=true}.
 *
 * <h3>Why WARN-by-default and not fail-fast-by-default</h3>
 * "MFA armed with no factor key" is not a hypothetical — it is a REACHABLE degraded state.
 * hugmesh-generator {@code specs/cluster/manifests/admin-bff-api/deployment.yaml} sets
 * {@code APP_CASDOOR_MFA_ENABLED: "true"} and sources {@code APP_MFA_FACTOR_KEY} from an
 * External-Secrets {@code secretKeyRef}. As of the 2.4.2 release chain that ref is REQUIRED
 * (generator {@code fix/mfa-factor-key-required}): in-cluster, a fully absent Secret is now a
 * {@code CreateContainerConfigError} the scheduler reports before this guard ever runs.
 * Historically the ref was {@code optional: true} ("<i>so the pod still starts if the Secret is
 * somehow absent</i>"), and the degraded state remains reachable everywhere the scheduler cannot
 * front it: a Secret PRESENT with an empty/blank value, compose, bare-metal runs, and any cluster
 * still applying the pre-tightening manifest. The same is true of the WebAuthn Relying Party: the
 * local compose stack runs MFA on with NEITHER {@code rp-id} nor {@code origins} set, and its
 * {@code dev} profile is only a DEFAULT ({@code ADMIN_BFF_PROFILES}) that an operator may drop.
 *
 * <p>admin-bff-api is the ONLY service that component-scans this package, and it is the
 * admin/superadmin control plane plus the gateway's cookie-to-JWT
 * {@code POST /bff/internal/session/exchange} leg. Turning those tolerated states into a throw
 * would therefore CrashLoopBackOff the entire privileged plane on a fresh cluster bring-up (before
 * ESO has synced), on a new brand/tenant where {@code gen-cluster-secrets} was not re-run, or on a
 * Vault path typo — locking operators out of the very plane they would use to fix it. That is
 * strictly worse than the user-level lockout this class exists to surface. So the default is to
 * TELL the operator, precisely and unmissably, and keep serving; making it fatal is an explicit,
 * per-deployment decision.
 *
 * <p>(No actuator health indicator is offered: this library has no
 * {@code spring-boot-actuator} dependency and no health-contributor precedent, and a shared
 * auth jar is the wrong place to acquire one.)
 *
 * <h3>Precondition 1 — the recovery-code lockout ({@code app.mfa.factor-key})</h3>
 * {@code app.mfa.factor-key} gates TOTP ({@link MfaSecretCipher}) and recovery codes
 * ({@link RecoveryCodeService}) but NOT WebAuthn ({@link WebAuthnService} needs no key). So
 * enabling MFA with no key yields WEBAUTHN-ONLY MFA in which TOTP enrollment and
 * {@link MfaEnrollmentService#regenerateRecoveryCodes} both 503 — a user who loses their passkey
 * is then locked out with NO self-service recovery path, and nothing in the logs says why. This
 * check exists to make that state impossible to run into unknowingly. (The recovery-code crypto is
 * deliberately keyed HMAC-SHA256 and stays keyed — the answer is to provision the key, never to
 * weaken the hash.)
 *
 * <h3>Precondition 2 — the WebAuthn RP silent-localhost default</h3>
 * {@code app.mfa.webauthn.rp-id} / {@code app.mfa.webauthn.origins} default to
 * {@code localhost} / {@code https://localhost} (dev-correct, and {@link WebAuthnService} keeps
 * those defaults). A deployed instance that forgets to override them starts happily and then
 * registers every passkey against the WRONG Relying Party, so nothing works and no error explains
 * it. Outside a dev profile, a loopback (or absent) RP ID / origin allowlist is therefore reported.
 * Under a dev profile it is not a problem at all — merely noted — because loopback is the correct
 * answer there.
 *
 * <h3>Dev detection — the explicit rule</h3>
 * "Dev" means one of {@value #DEV_PROFILE_LIST} is among {@link Environment#getActiveProfiles()}.
 * These are exactly the profile names in the predicate the library's other prod-only boot guard
 * uses ({@code InternalSurfaceBootGuard}'s {@code @Profile("!dev & !test")}), so auth-core has ONE
 * dev rule, not two. The only difference is bean PRESENCE, not the rule: this bean is
 * {@code @Profile("!test")} rather than {@code !dev & !test} because it still has something useful
 * to say under {@code dev} (the loopback-RP note), whereas the mTLS guard has nothing to do there.
 *
 * <p>That signal is already LOAD-BEARING rather than merely conventional: a plaintext local run of
 * a consumer BFF cannot boot at all without the {@code dev} profile, because
 * {@code InternalSurfaceBootGuard} refuses to serve {@code /bff/internal/**} without mTLS
 * otherwise. The local compose stack runs {@code SPRING_PROFILES_ACTIVE=casdoor,dev} and sets no
 * RP ID, so it stays exempt; the cluster runs {@code SPRING_PROFILES_ACTIVE=casdoor,clickhouse}
 * and does set a real RP ID, so it passes on the merits. An unprofiled deployment counts as NOT
 * dev — the safe direction for a passkey RP ID.
 *
 * <h3>Blast radius — MFA OFF is byte-identical to today</h3>
 * EVERY check here is behind {@code app.casdoor.mfa.enabled} (default false in every consumer's
 * {@code application.yml}). With MFA off this class logs at debug and returns. With MFA on it can
 * still only log, unless {@code app.mfa.preconditions.fail-fast=true} is explicitly set — so no
 * existing deployment of this shared library can acquire a startup failure from adopting it. The
 * bean is additionally absent under the {@code test} profile, mirroring the existing guard.
 *
 * <p>Implementation note: it is a {@link SmartInitializingSingleton} because that runs after every
 * singleton exists (so {@link MfaSecretCipher}/{@link RecoveryCodeService} can be asked whether
 * they are actually usable) and because a throw there aborts context refresh — which is what the
 * opt-in needs.
 */
@Component
@Profile("!test")
public class MfaPreconditionBootGuard implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(MfaPreconditionBootGuard.class);

    /** The dark gate every check here is behind — MFA is OFF by default in every consumer. */
    static final String PROP_MFA_ENABLED = "app.casdoor.mfa.enabled";
    /** The secret-store key that gates BOTH the TOTP cipher and the recovery-code HMAC. */
    static final String PROP_FACTOR_KEY = "app.mfa.factor-key";
    /** The WebAuthn Relying Party ID (the registrable domain). */
    static final String PROP_RP_ID = "app.mfa.webauthn.rp-id";
    /** The CSV WebAuthn origin allowlist. */
    static final String PROP_ORIGINS = "app.mfa.webauthn.origins";
    /**
     * OPT-IN escalation: {@code false} (the default) reports unmet preconditions as a WARN and
     * starts anyway; {@code true} makes them abort the boot. Env {@code
     * APP_MFA_PRECONDITIONS_FAIL_FAST}. Deliberately default-off — see the class javadoc: the
     * states it detects are tolerated in the shipped manifests, so defaulting to a throw would
     * CrashLoopBackOff the admin plane.
     */
    static final String PROP_FAIL_FAST = "app.mfa.preconditions.fail-fast";

    /** The env-var spelling of {@link #PROP_FAIL_FAST}, quoted in both messages. */
    static final String ENV_FAIL_FAST = "APP_MFA_PRECONDITIONS_FAIL_FAST";

    /** The unmissable marker both the WARN and the failure carry, for log alerting/grep. */
    static final String BANNER = "*** MFA MISCONFIGURED ***";

    /** Documentation-only rendering of {@link #DEV_PROFILES} for the class javadoc. */
    static final String DEV_PROFILE_LIST = "dev, test";

    /**
     * Profiles that mean "this is a developer/CI run, loopback is legitimate". EXACTLY the profile
     * names in {@code InternalSurfaceBootGuard}'s {@code @Profile("!dev & !test")}, so the library
     * has one dev rule. {@code test} is included belt-and-braces even though
     * {@code @Profile("!test")} already removes this bean there.
     */
    private static final Set<String> DEV_PROFILES = Set.of("dev", "test");

    /**
     * Host names that are the loopback interface, i.e. only ever reachable from the machine
     * running the browser. {@code 0.0.0.0} is not literally loopback but is never a valid RP ID
     * either, so it belongs in the same reject set. NOTE: mDNS {@code *.local} is deliberately
     * ABSENT — a LAN deployment may legitimately be named {@code foo.local} and reporting that
     * would be a false alarm.
     */
    private static final Set<String> LOOPBACK_HOSTS =
            Set.of("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0");

    private final boolean mfaEnabled;
    private final boolean failFast;
    private final String rpId;
    private final String originsCsv;
    private final boolean devProfileActive;
    private final MfaSecretCipher cipher;
    private final RecoveryCodeService recoveryCodes;

    @Autowired
    public MfaPreconditionBootGuard(
            @Value("${" + PROP_MFA_ENABLED + ":false}") boolean mfaEnabled,
            @Value("${" + PROP_FAIL_FAST + ":false}") boolean failFast,
            // Read with a BLANK default (not localhost) so "absent" and "explicitly localhost"
            // are distinguishable in the message. WebAuthnService keeps its own localhost
            // defaults — this class does not change any runtime default.
            @Value("${" + PROP_RP_ID + ":}") String rpId,
            @Value("${" + PROP_ORIGINS + ":}") String originsCsv,
            MfaSecretCipher cipher,
            RecoveryCodeService recoveryCodes,
            Environment environment) {
        this(mfaEnabled, failFast, rpId, originsCsv, cipher, recoveryCodes,
                isDevLike(environment == null ? null : environment.getActiveProfiles()));
    }

    /** Profile-resolved form (the unit-test seam) — {@code devProfileActive} already decided. */
    MfaPreconditionBootGuard(boolean mfaEnabled,
                             boolean failFast,
                             String rpId,
                             String originsCsv,
                             MfaSecretCipher cipher,
                             RecoveryCodeService recoveryCodes,
                             boolean devProfileActive) {
        this.mfaEnabled = mfaEnabled;
        this.failFast = failFast;
        this.rpId = rpId == null ? "" : rpId.trim();
        this.originsCsv = originsCsv == null ? "" : originsCsv.trim();
        this.cipher = cipher;
        this.recoveryCodes = recoveryCodes;
        this.devProfileActive = devProfileActive;
    }

    /**
     * True when any active profile is developer/CI-shaped. Null/empty active profiles (i.e. only
     * Spring's implicit {@code default}) is NOT dev — an unprofiled deployment gets the strict
     * treatment, which is the safe direction for a passkey RP ID.
     */
    static boolean isDevLike(String[] activeProfiles) {
        if (activeProfiles == null) {
            return false;
        }
        return Arrays.stream(activeProfiles)
                .filter(p -> p != null)
                .map(p -> p.trim().toLowerCase(Locale.ROOT))
                .anyMatch(DEV_PROFILES::contains);
    }

    /** True when {@code host} is the loopback interface (see {@link #LOOPBACK_HOSTS}). */
    static boolean isLoopbackHost(String host) {
        if (host == null) {
            return false;
        }
        String h = host.trim().toLowerCase(Locale.ROOT);
        // Tolerate a fully-qualified trailing dot ("localhost.").
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.isEmpty()) {
            return false;
        }
        // RFC 6761 reserves the whole .localhost tree for loopback.
        return LOOPBACK_HOSTS.contains(h) || h.endsWith(".localhost");
    }

    /**
     * True when EVERY entry in the CSV origin allowlist is a loopback origin (so no deployed
     * browser origin can ever pass the ceremony). A blank list is also "no usable origin".
     * An entry whose host cannot be parsed counts as NON-loopback — an exotic-but-valid origin
     * must never be the reason an alarm is raised.
     */
    static boolean isAllLoopbackOrigins(String csv) {
        if (csv == null || csv.isBlank()) {
            return true;
        }
        for (String raw : csv.split(",")) {
            String origin = raw.trim();
            if (origin.isEmpty()) {
                continue; // WebAuthnService skips blank entries too
            }
            if (!isLoopbackHost(hostOf(origin))) {
                return false;
            }
        }
        // Every usable entry was loopback — including the zero-usable-entry case (e.g. " , "),
        // where WebAuthnService falls back to https://localhost anyway.
        return true;
    }

    /** The host component of an origin, or null when it cannot be determined. */
    private static String hostOf(String origin) {
        try {
            URI uri = URI.create(origin);
            if (uri.getHost() != null) {
                return uri.getHost();
            }
            // URI.getHost() is null for e.g. "https://::1" / underscored hosts; fall back to a
            // literal scheme-strip so those still classify rather than silently pass.
            String rest = uri.getSchemeSpecificPart();
            if (rest == null) {
                return null;
            }
            rest = rest.startsWith("//") ? rest.substring(2) : rest;
            int slash = rest.indexOf('/');
            if (slash >= 0) {
                rest = rest.substring(0, slash);
            }
            // Strip a trailing :port, but keep a bracketed IPv6 literal intact.
            int colon = rest.lastIndexOf(':');
            if (colon > rest.lastIndexOf(']') && colon >= 0) {
                rest = rest.substring(0, colon);
            }
            return rest.isEmpty() ? null : rest;
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!mfaEnabled) {
            // THE blast-radius guarantee: MFA off (the consumer default) => nothing is reported.
            // Behaviour is byte-identical to before this class existed.
            log.debug("[mfa-preconditions] {}=false — MFA preconditions not checked (ships dark)",
                    PROP_MFA_ENABLED);
            return;
        }

        List<String> problems = new ArrayList<>(3);
        checkFactorKey(problems);
        checkWebAuthnRelyingParty(problems);

        if (problems.isEmpty()) {
            log.info("[mfa-preconditions] MFA enabled and preconditions OK (factor key present, "
                    + "WebAuthn rp-id='{}'{}) — boot OK",
                    rpId.isEmpty() ? "localhost (default)" : rpId,
                    devProfileActive ? ", dev profile" : "");
            return;
        }

        String detail = detail(problems);
        if (failFast) {
            throw new IllegalStateException(
                    "REFUSING TO BOOT: " + BANNER + " " + detail + " This is FATAL because "
                    + PROP_FAIL_FAST + "=true (" + ENV_FAIL_FAST + "). Fix the properties named "
                    + "above, or unset " + PROP_FAIL_FAST + " to downgrade this to a startup WARN, "
                    + "or set " + PROP_MFA_ENABLED + "=false to keep MFA dark.");
        }
        // NOT fatal by default, on purpose: see the class javadoc. Say it as loudly as a log line
        // can, name every property and env var, and state what the operator loses meanwhile.
        log.warn("[mfa-preconditions] {} {} >>> THE APPLICATION IS STARTING ANYWAY: these are "
                + "WARN-only by default because they are tolerated degraded states in the shipped "
                + "manifests, and aborting the boot of the admin control plane would be worse than "
                + "the degradation. NOTHING ELSE WILL TELL YOU THIS AGAIN. Set {}=true ({}) to "
                + "make it a hard boot failure instead, or set {}=false to keep MFA dark.",
                BANNER, detail, PROP_FAIL_FAST, ENV_FAIL_FAST, PROP_MFA_ENABLED);
    }

    /** The shared body of the WARN and of the opt-in failure, so neither can drift from the other. */
    private String detail(List<String> problems) {
        return "MFA is ENABLED (" + PROP_MFA_ENABLED + "=true) but " + problems.size()
                + " of its preconditions are NOT met, so MFA is silently broken and/or silently "
                + "unrecoverable for users: " + String.join(" ", problems);
    }

    /** PRECONDITION 1 — a usable {@code app.mfa.factor-key}, else recovery codes are impossible. */
    private void checkFactorKey(List<String> problems) {
        boolean cipherReady = cipher != null && cipher.isAvailable();
        boolean recoveryReady = recoveryCodes != null && recoveryCodes.isAvailable();
        if (cipherReady && recoveryReady) {
            return;
        }
        // Ask the two components that actually 503 rather than re-deriving the key here, so this
        // check can never drift from the behaviour it is protecting.
        problems.add("[" + PROP_FACTOR_KEY + "] is NOT CONFIGURED, so TOTP enrollment AND "
                + "RECOVERY-CODE generation both fail with 503 while WebAuthn still works — i.e. "
                + "WebAuthn-only MFA with NO recovery path, in which a user who loses their passkey "
                + "is locked out with no self-service way back in (an operator must clear their "
                + "factors by hand). Provision a 256-bit key (env APP_MFA_FACTOR_KEY, from "
                + "ESO/Vault; base64/base64url 32 bytes preferred).");
    }

    /** PRECONDITION 2 — a real WebAuthn Relying Party outside dev, else every passkey is wrong. */
    private void checkWebAuthnRelyingParty(List<String> problems) {
        boolean rpIdLoopback = rpId.isEmpty() || isLoopbackHost(rpId);
        boolean originsLoopback = isAllLoopbackOrigins(originsCsv);

        if (devProfileActive) {
            // The local compose stack legitimately runs the WebAuthn ceremony on localhost and
            // sets NEITHER property. Not a problem here at all — not even under fail-fast, or
            // an operator who armed the opt-in fleet-wide would break their own dev stack.
            if (rpIdLoopback || originsLoopback) {
                log.warn("[mfa-preconditions] dev profile active — WebAuthn Relying Party is "
                        + "LOOPBACK ({}='{}', {}='{}'); passkeys will only register/assert from "
                        + "a localhost browser origin. A deployed instance MUST set both.",
                        PROP_RP_ID, rpId.isEmpty() ? "<unset, defaults to localhost>" : rpId,
                        PROP_ORIGINS,
                        originsCsv.isEmpty() ? "<unset, defaults to https://localhost>" : originsCsv);
            }
            return;
        }

        if (rpIdLoopback) {
            problems.add("[" + PROP_RP_ID + "] is "
                    + (rpId.isEmpty() ? "absent (it silently defaults to 'localhost')"
                                      : "'" + rpId + "', a loopback host")
                    + " on a non-dev deployment, so every passkey would be registered against the "
                    + "WRONG Relying Party and no WebAuthn ceremony could ever succeed. Set it to "
                    + "the registrable domain the browser actually loads (env "
                    + "APP_MFA_WEBAUTHN_RP_ID, e.g. admin.hugmesh.systems).");
        }
        if (originsLoopback) {
            problems.add("[" + PROP_ORIGINS + "] is "
                    + (originsCsv.isEmpty() ? "absent (it silently defaults to 'https://localhost')"
                                            : "'" + originsCsv + "', all loopback origins")
                    + " on a non-dev deployment, so the ceremony would reject every real browser "
                    + "origin. Set the CSV allowlist to the deployed https origin(s) (env "
                    + "APP_MFA_WEBAUTHN_ORIGINS, e.g. https://admin.hugmesh.systems).");
        }
    }
}

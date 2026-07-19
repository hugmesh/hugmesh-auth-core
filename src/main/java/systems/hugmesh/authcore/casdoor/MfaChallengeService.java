package systems.hugmesh.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.account.AccountStore;

/**
 * Orchestrates the A4 BFF-driven MFA challenge DUAL-STAMP (WAVE-2 plan of record). On a
 * provably-successful second-factor verification it writes TWO places, neither
 * bypassable:
 *
 * <ol>
 *   <li><b>AUTHORITATIVE (session-scoped, immediate):</b>
 *       {@code UPDATE bff_session SET mfa_satisfied=true, mfa_satisfied_at=now()} for the
 *       caller's EXACT session token ({@link AccountStore#stampMfaSatisfied}). This is the
 *       source of truth the four step-up gates + {@code /bff/session} read; NO cross-session
 *       bleed (it is keyed on the one session token).</li>
 *   <li><b>ADVISORY (user-scoped, eventually-consistent):</b> the Casdoor user
 *       {@code mfa_satisfied_at} Property = epoch-millis NUMERIC STRING via
 *       {@link CasdoorAdminClient#writeMfaProperty} (GET-then-MERGE +
 *       {@code &columns=properties}, sibling-preserving) so a freshly-minted raw JWT carries
 *       the gateway-readable claim. Best-effort: a Casdoor-less run (no admin client bean)
 *       or a transport error never fails the challenge.</li>
 * </ol>
 * After the writes it FORCE-REFRESHes the raw-JWT client ({@link RawJwtRefreshService}) so
 * the gateway sees the claim within the freshness window (or applies the documented
 * natural-lifetime fallback).
 *
 * <h3>Ships dark / fail-closed</h3>
 * Gated by {@code app.casdoor.mfa.enabled} (DEFAULT false) — the SAME flag the
 * {@link MfaStepUpService} step-up leg reads. When dark, {@link #challenge} resolves
 * {@code false} WITHOUT verifying or stamping (the controller 503s before reaching here;
 * this is belt-and-suspenders). The subject/username are taken from the validated JWT
 * (NEVER a body field). A verification that does not provably succeed stamps NOTHING.
 */
@Service
public class MfaChallengeService {

    private static final Logger log = LoggerFactory.getLogger(MfaChallengeService.class);

    private final AccountStore store;
    private final MfaFactorVerifier verifier;
    private final RawJwtRefreshService refresh;
    /** The Casdoor admin write client — {@code null} when {@code casdoor.admin.enabled=false}
     *  (Casdoor-less / unit run). The advisory Property write is then skipped; the
     *  authoritative session stamp still lands. */
    @Nullable
    private final CasdoorAdminClient casdoor;
    /** {@code app.casdoor.mfa.enabled} — the dark gate (default false), shared with the
     *  step-up leg. */
    private final boolean enabled;

    public MfaChallengeService(AccountStore store,
                               MfaFactorVerifier verifier,
                               RawJwtRefreshService refresh,
                               @Nullable CasdoorAdminClient casdoor,
                               MfaStepUpService stepUp) {
        this.store = store;
        this.verifier = verifier;
        this.refresh = refresh;
        this.casdoor = casdoor;
        // Read the dark flag off the SAME source the step-up leg uses, so the two legs
        // can never disagree about whether MFA is armed.
        this.enabled = stepUp.enabled();
    }

    /** Whether the BFF-driven MFA challenge is ARMED ({@code app.casdoor.mfa.enabled}). */
    public boolean enabled() {
        return enabled;
    }

    /**
     * Run the challenge for the caller. {@code subject}/{@code username} come from the
     * validated JWT; {@code sessionToken} is the caller's opaque {@code bff_} token
     * (cookie- or Bearer-borne). Resolves {@code true} iff the factor verified AND the
     * authoritative session stamp landed (rows updated &gt; 0). Fail-closed: dark, no
     * subject, no session token, or a failed verification all resolve {@code false} with
     * NO stamp written.
     */
    public Mono<Boolean> challenge(String subject, String username, String sessionToken,
                                   MfaFactorVerifier.Factor factor, String credential) {
        if (!enabled) {
            return Mono.just(false);
        }
        if (subject == null || subject.isBlank() || factor == null) {
            return Mono.just(false);
        }
        return verifier.verify(subject, username, factor, credential)
                .defaultIfEmpty(false)
                .onErrorResume(e -> {
                    log.debug("[mfa-challenge] factor verify failed (fail-closed): {}", e.toString());
                    return Mono.just(false);
                })
                .flatMap(verified -> onVerified(verified, subject, username, sessionToken, factor));
    }

    /** When verified=true: stamp the session, write advisory, force-refresh; else resolve false. */
    private Mono<Boolean> onVerified(Boolean verified, String subject, String username,
                                     String sessionToken, MfaFactorVerifier.Factor factor) {
        if (!Boolean.TRUE.equals(verified)) {
            log.debug("[mfa-challenge] factor not verified -> no stamp");
            return Mono.just(false);
        }
        // (a) AUTHORITATIVE: stamp the caller's exact session (immediate, no bleed).
        return store.stampMfaSatisfied(sessionToken, factor.amr())
                .flatMap(rows -> onSessionStamped(rows, subject, username));
    }

    /** After the authoritative session stamp: write advisory + force-refresh, or fail-closed. */
    private Mono<Boolean> onSessionStamped(Long rows, String subject, String username) {
        if (rows == null || rows == 0L) {
            // No session row to stamp (unknown/expired token) -> the
            // verification succeeded but there is nothing to satisfy.
            log.debug("[mfa-challenge] verified but no session row stamped");
            return Mono.just(false);
        }
        // (b) ADVISORY + (c) FORCE-REFRESH: best-effort, never fail the challenge.
        return writeAdvisory(username)
                .then(refresh.forceRefresh(subject, null))
                .thenReturn(true)
                .onErrorResume(e -> {
                    log.warn("[mfa-challenge] advisory leg best-effort failure "
                            + "(session stamp already landed): {}", e.toString());
                    return Mono.just(true);
                });
    }

    /** ADVISORY user-Property write — no-op when no admin client is wired (Casdoor-less run). */
    private Mono<Void> writeAdvisory(String username) {
        if (casdoor == null || username == null || username.isBlank()) {
            return Mono.empty();
        }
        return casdoor.writeMfaProperty(username, System.currentTimeMillis());
    }

    /**
     * CLEAR the Casdoor {@code mfa_satisfied_at} Property for {@code username} on logout
     * (bounds the cross-session bleed window). No-op when no admin client is wired or the
     * username is blank. Best-effort — logout never fails on a Casdoor hiccup.
     */
    public Mono<Void> clearProperty(String username) {
        if (casdoor == null || username == null || username.isBlank()) {
            return Mono.empty();
        }
        return casdoor.clearMfaProperty(username)
                .onErrorResume(e -> {
                    log.debug("[mfa-challenge] clear-property best-effort failure: {}", e.toString());
                    return Mono.empty();
                });
    }
}

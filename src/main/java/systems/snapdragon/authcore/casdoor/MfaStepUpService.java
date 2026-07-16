package systems.snapdragon.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.account.AccountStore;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * The Casdoor-MFA leg of the unified STEP-UP gate (A5). A FRESH {@code bff_session}
 * MFA stamp is a CO-EQUAL, LICENSE-INDEPENDENT satisfier of step-up alongside the
 * existing short-TTL {@code WorkloadStepUpService} token (admin-bff — not part of this
 * jar). This service answers the single question the four step-up gates
 * (DeviceTerminal / ImageGen / SshKeyIssue / Backup) ask the MFA leg:
 *
 * <blockquote>does the opaque session carried by this request have a FRESH MFA
 * satisfaction (within the configurable freshness window)?</blockquote>
 *
 * <h3>Ships dark, fail-closed</h3>
 * Gated by {@code app.casdoor.mfa.enabled} (DEFAULT false). When disabled this leg
 * NEVER satisfies — only the workload step-up token leg works, exactly as today. When
 * enabled, a session satisfies ONLY when {@code bff_session.mfa_satisfied} is true AND
 * {@code now - mfa_satisfied_at <= app.casdoor.mfa.freshness} (DEFAULT 10m, the
 * user-chosen window). {@code mfa_satisfied} DEFAULTS false at the schema (band 150), so
 * a never-stamped session fails CLOSED; a STALE stamp (past the window) also fails closed.
 *
 * <h3>License independence</h3>
 * The MFA leg deliberately does NO device/SSH-license check — a superadmin NON-device op
 * (e.g. cloud-backup restore) can step up with a fresh MFA stamp and NO
 * {@code device_ssh_license}. DEVICE ops still ALSO require the license precondition, but
 * that precondition lives DOWNSTREAM in the device service layer (the SSH-license registry
 * the dial/remote-install service consults), NOT in this satisfier — so wiring the MFA leg
 * into a device gate does not weaken the license requirement.
 *
 * <h3>Single-use / freshness consumption</h3>
 * The freshness window is the single-use bound for the MFA leg: a privileged mutation
 * consumes the freshness by calling {@link #consume(String)}, which clears the stamp so a
 * second mutation needs a fresh MFA challenge. Bound to the exact session token (the lookup
 * is by token PK), constant-time at the carrier comparison (the token equality the cookie
 * bridge / Bearer header funnel through).
 */
@Service
public class MfaStepUpService {

    private static final Logger log = LoggerFactory.getLogger(MfaStepUpService.class);

    private final AccountStore store;
    private final boolean enabled;
    private final Duration freshness;

    public MfaStepUpService(
            AccountStore store,
            @Value("${app.casdoor.mfa.enabled:false}") boolean enabled,
            @Value("${app.casdoor.mfa.freshness:PT10M}") Duration freshness) {
        this.store = store;
        this.enabled = enabled;
        // A non-positive / unset window degrades to the 10m default rather than
        // "every stamp is stale" (which would silently disable the leg).
        this.freshness = (freshness == null || freshness.isZero() || freshness.isNegative())
                ? Duration.ofMinutes(10) : freshness;
    }

    /** Whether the Casdoor-MFA step-up leg is ARMED. When false the leg never satisfies. */
    public boolean enabled() {
        return enabled;
    }

    /** The configured freshness window (the A5 user-chosen window; default 10m). */
    public Duration freshness() {
        return freshness;
    }

    /**
     * True iff the opaque session token carries a FRESH MFA satisfaction. Fail-closed:
     * the leg is disabled, the token is null/blank/non-{@code bff_}, the session is
     * unknown/expired, never stamped, or the stamp is STALE (past the freshness window)
     * all resolve to {@code false}. Resolves {@code true} ONLY when the leg is enabled AND
     * {@code mfa_satisfied} AND {@code now - mfa_satisfied_at <= freshness}.
     */
    public Mono<Boolean> isFresh(String sessionToken) {
        if (!enabled || sessionToken == null || sessionToken.isBlank()) {
            return Mono.just(false);
        }
        return store.mfaStateOf(sessionToken)
                .map(this::freshSnapshot)
                .defaultIfEmpty(false);
    }

    /** Freshness predicate over an already-loaded MFA snapshot (testable in isolation).
     *  Distinct name from {@link #isFresh(String)} so a {@code mock.isFresh(any())} stub is
     *  unambiguous. */
    public boolean freshSnapshot(AccountStore.MfaState state) {
        if (!enabled || state == null || !state.satisfied()) {
            return false;
        }
        LocalDateTime at = state.satisfiedAt();
        if (at == null) {
            // satisfied flag true but no timestamp -> cannot prove freshness -> fail closed.
            return false;
        }
        LocalDateTime cutoff = LocalDateTime.now().minus(freshness);
        boolean fresh = !at.isBefore(cutoff);
        if (!fresh) {
            log.debug("[mfa-stepup] stale MFA stamp (older than {}m) -> not satisfied",
                    freshness.toMinutes());
        }
        return fresh;
    }

    /**
     * Consume (single-use) the MFA freshness for the session after a privileged mutation:
     * clears the stamp so a second privileged mutation requires a fresh MFA challenge. No-op
     * when the leg is disabled or the token is blank. Returns silently (best-effort, the
     * mutation already happened); a failed clear is logged.
     */
    public Mono<Void> consume(String sessionToken) {
        if (!enabled || sessionToken == null || sessionToken.isBlank()) {
            return Mono.empty();
        }
        return store.clearMfaSatisfied(sessionToken)
                .doOnError(e -> log.warn("[mfa-stepup] freshness consume failed (best-effort): {}",
                        e.toString()))
                .onErrorResume(e -> Mono.empty())
                .then();
    }
}

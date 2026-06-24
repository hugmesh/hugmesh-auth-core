package systems.snapdragon.authcore.mfa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.snapdragon.authcore.casdoor.MfaFactorVerifier;

/**
 * The REAL {@link MfaFactorVerifier} — replaces the deny-all default in
 * {@code MfaChallengeConfig} (it is {@link Primary} + a concrete bean, so the
 * {@code @ConditionalOnMissingBean} default no longer registers). For the existing
 * {@code POST /bff/mfa/challenge} it verifies the presented factor against the CALLER'S
 * BFF-stored factors:
 *
 * <ul>
 *   <li><b>TOTP</b> — decrypt the AES-GCM secret of the caller's ENABLED TOTP factor, verify
 *       the code (±1 step skew), REJECT replay of the just-used step, and advance the stored
 *       replay floor on success.</li>
 *   <li><b>RECOVERY</b> — constant-time keyed-hash compare against the caller's UNUSED
 *       recovery codes; consume (one-time) the matched code via a CAS.</li>
 *   <li><b>WEBAUTHN</b> — verify the assertion signature + RP ID + origin + challenge (the
 *       pending assertion challenge issued to this subject) + SIGN-COUNT monotonicity (clone
 *       detection), then advance the stored sign count.</li>
 * </ul>
 *
 * <h3>Fail-closed (the verifier contract)</h3>
 * ONLY a provably-successful verification against an ENABLED factor resolves {@code true};
 * EVERYTHING else (unknown subject, no matching factor, disabled factor, replay, missing
 * challenge, transport error, any exception) resolves {@code false} and NEVER throws. The
 * owner is the JWT {@code subject} the {@code MfaChallengeController} passes — never a body
 * field — so a caller can only satisfy a challenge with THEIR OWN factors.
 */
@Component
@Primary
public class BffStoredMfaFactorVerifier implements MfaFactorVerifier {

    private static final Logger log = LoggerFactory.getLogger(BffStoredMfaFactorVerifier.class);

    private final MfaFactorR2dbcRepository factors;
    private final MfaRecoveryCodeR2dbcRepository recoveryCodes;
    private final WebAuthnCredentialR2dbcRepository webauthnCredentials;
    private final MfaSecretCipher cipher;
    private final TotpService totp;
    private final RecoveryCodeService recovery;
    private final WebAuthnService webauthn;
    private final WebAuthnChallengeStore challenges;

    public BffStoredMfaFactorVerifier(MfaFactorR2dbcRepository factors,
                                      MfaRecoveryCodeR2dbcRepository recoveryCodes,
                                      WebAuthnCredentialR2dbcRepository webauthnCredentials,
                                      MfaSecretCipher cipher,
                                      TotpService totp,
                                      RecoveryCodeService recovery,
                                      WebAuthnService webauthn,
                                      WebAuthnChallengeStore challenges) {
        this.factors = factors;
        this.recoveryCodes = recoveryCodes;
        this.webauthnCredentials = webauthnCredentials;
        this.cipher = cipher;
        this.totp = totp;
        this.recovery = recovery;
        this.webauthn = webauthn;
        this.challenges = challenges;
    }

    @Override
    public Mono<Boolean> verify(String subject, String username, Factor factor, String credential) {
        if (subject == null || subject.isBlank() || factor == null || credential == null) {
            return Mono.just(false);
        }
        Mono<Boolean> result = switch (factor) {
            case TOTP -> verifyTotp(subject, credential);
            case RECOVERY -> verifyRecovery(subject, credential);
            case WEBAUTHN -> verifyWebAuthn(subject, credential);
        };
        // The verifier contract: NEVER throw — any error is a fail-closed false.
        return result.defaultIfEmpty(false)
                .onErrorResume(e -> {
                    log.debug("[mfa-verify] factor verify error (fail-closed): {}", e.toString());
                    return Mono.just(false);
                });
    }

    // ── TOTP ────────────────────────────────────────────────────────────────────────────
    private Mono<Boolean> verifyTotp(String subject, String code) {
        return factors.findByOwnerSubjectAndType(subject, MfaFactorRow.TYPE_TOTP)
                .filter(MfaFactorRow::enabled) // only ENABLED factors satisfy
                .concatMap(row -> verifyTotpRow(subject, code, row))
                .filter(Boolean::booleanValue)
                .next()
                .defaultIfEmpty(false);
    }

    /** Verify a single TOTP factor row: decrypt secret, check code, advance replay floor. */
    private Mono<Boolean> verifyTotpRow(String subject, String code, MfaFactorRow row) {
        String secret = cipher.decrypt(row.totpSecretEnc());
        if (secret == null) {
            return Mono.just(false);
        }
        long floor = row.lastCounter() == null ? -1L : row.lastCounter();
        long step = totp.verify(secret, floor, code);
        if (step < 0) {
            return Mono.just(false);
        }
        // Advance the replay floor; the SQL guard (last_counter < step) makes a
        // concurrent replay of the same step lose -> 0 rows -> not satisfied.
        return factors.advanceCounter(row.id(), subject, step)
                .map(rows -> rows != null && rows > 0L);
    }

    // ── recovery code ─────────────────────────────────────────────────────────────────
    private Mono<Boolean> verifyRecovery(String subject, String code) {
        return recoveryCodes.findByOwnerSubjectAndUsedFalse(subject)
                .filter(row -> recovery.matches(code, row.codeHash()))
                .next()
                .flatMap(row -> recoveryCodes.consume(row.id(), subject)
                        // CAS: one-time consume; a concurrent double-spend loses (0 rows).
                        .map(rows -> rows != null && rows > 0L))
                .defaultIfEmpty(false);
    }

    // ── WebAuthn assertion ──────────────────────────────────────────────────────────────
    private Mono<Boolean> verifyWebAuthn(String subject, String assertionJson) {
        // The pending assertion challenge was issued to THIS subject (challenge-time).
        return challenges.consume(subject, WebAuthnChallengeStore.PURPOSE_ASSERT)
                .flatMap(challenge -> verifyWebAuthnWithChallenge(subject, assertionJson, challenge))
                .defaultIfEmpty(false);
    }

    private Mono<Boolean> verifyWebAuthnWithChallenge(String subject, String assertionJson,
                                                      String challenge) {
        String credentialId = webauthn.credentialIdOfAssertion(assertionJson);
        if (credentialId == null) {
            return Mono.just(false);
        }
        return webauthnCredentials.findByCredentialId(credentialId)
                // OWNER GUARD: the credential must belong to the asserting subject + be enabled.
                .filter(c -> subject.equals(c.ownerSubject()) && c.enabled())
                .flatMap(cred -> verifyAndAdvanceSignCount(subject, assertionJson, challenge, cred))
                .defaultIfEmpty(false);
    }

    /** Verify the WebAuthn assertion then advance the stored sign count (clone backstop). */
    private Mono<Boolean> verifyAndAdvanceSignCount(String subject, String assertionJson,
                                                    String challenge,
                                                    WebAuthnCredentialRow cred) {
        return Mono.fromCallable(() ->
                        webauthn.verifyAssertion(assertionJson, challenge,
                                cred.publicKeyCose(), cred.signCount()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(newCount -> advanceSignCountIfChanged(subject, cred, newCount))
                .onErrorResume(WebAuthnService.WebAuthnException.class,
                        e -> Mono.just(false));
    }

    /** Advance the sign count monotonically; accept a genuine always-0-counter authenticator. */
    private Mono<Boolean> advanceSignCountIfChanged(String subject, WebAuthnCredentialRow cred,
                                                    long newCount) {
        // Advance the sign count monotonically. The SQL guard
        // (sign_count < newCount) is the clone backstop; for a genuine
        // always-0-counter authenticator (stored 0, new 0) WebAuthn4J
        // already passed the assertion, so accept without an advance.
        if (newCount > cred.signCount()) {
            return webauthnCredentials
                    .advanceSignCount(cred.id(), subject, newCount)
                    .map(rows -> rows != null && rows > 0L);
        }
        return Mono.just(cred.signCount() == 0L && newCount == 0L);
    }
}

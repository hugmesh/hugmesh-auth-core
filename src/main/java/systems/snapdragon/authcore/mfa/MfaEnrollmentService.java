package systems.snapdragon.authcore.mfa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;
import java.util.List;

/**
 * The BFF-OWNED MFA factor lifecycle (enroll / list / remove / recovery), the D6+D8 web
 * path. Casdoor cannot verify a factor on behalf of a session-less web user, so the BFF
 * generates the TOTP secret itself (AES-256-GCM at rest), runs its own WebAuthn ceremony,
 * and generates+hashes recovery codes.
 *
 * <h3>owner == authenticated subject ALWAYS</h3>
 * Every method takes the {@code ownerSubject} the controller pulls from the authenticated
 * principal (JWT {@code sub} / auth name) — NEVER a request-body field. A caller can only
 * enroll/list/remove THEIR OWN factors (the cross-user isolation keystone; the SQL is
 * owner-scoped too as a backstop).
 *
 * <h3>Ships dark</h3>
 * The controller 503s every endpoint while {@code app.casdoor.mfa.enabled=false}; this
 * service additionally refuses TOTP enroll / recovery generation when the secret-store key
 * is unconfigured ({@link MfaSecretCipher#isAvailable()}) so MFA is never armed without a
 * key (no plaintext-secret fallback).
 */
@Service
public class MfaEnrollmentService {

    private static final Logger log = LoggerFactory.getLogger(MfaEnrollmentService.class);

    private final MfaFactorR2dbcRepository factors;
    private final MfaRecoveryCodeR2dbcRepository recoveryCodes;
    private final WebAuthnCredentialR2dbcRepository webauthnCredentials;
    private final MfaSecretCipher cipher;
    private final TotpService totp;
    private final RecoveryCodeService recovery;
    private final WebAuthnService webauthn;
    private final WebAuthnChallengeStore challenges;

    public MfaEnrollmentService(MfaFactorR2dbcRepository factors,
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

    // ── TOTP enroll ───────────────────────────────────────────────────────────────────

    /**
     * Begin TOTP enroll: generate a CSPRNG base32 secret, store it AES-256-GCM-encrypted as
     * a DISABLED factor, and return the otpauth URI + the secret-for-QR (shown ONCE — the
     * secret is NEVER returned again). The factor stays {@code enabled=false} until a verify
     * proves the user can produce a code.
     */
    public Mono<TotpEnrollResult> beginTotpEnroll(String ownerSubject, String accountName) {
        if (!cipher.isAvailable()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "MFA factor key not provisioned — TOTP enroll unavailable"));
        }
        String secret = totp.newSecret();
        String enc = cipher.encrypt(secret);
        String otpauth = totp.otpauthUri(accountName, secret);
        // Insert a DISABLED TOTP factor (encrypted secret, null counter) and let Postgres mint
        // the id (gen_random_uuid() DEFAULT); RETURNING id gives us the factor id for the result.
        return factors.insertReturningId(ownerSubject, MfaFactorRow.TYPE_TOTP, enc,
                        null, false, Instant.now())
                .map(id -> new TotpEnrollResult(id, otpauth, secret));
    }

    /**
     * Finish TOTP enroll: verify {@code passcode} against the in-progress (disabled) TOTP
     * factor, flip it enabled (stamping the accepted step as the replay floor), and generate
     * + return a fresh set of recovery codes ONCE (store only their hashes). A wrong code is a
     * clean 401; the factor stays disabled.
     */
    public Mono<List<String>> verifyTotpEnroll(String ownerSubject, String passcode) {
        if (!cipher.isAvailable() || !recovery.isAvailable()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "MFA factor key not provisioned — TOTP enroll unavailable"));
        }
        return factors.findByOwnerSubjectAndType(ownerSubject, MfaFactorRow.TYPE_TOTP)
                .filter(f -> !f.enabled()) // the in-progress (disabled) row
                .next()
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no pending TOTP enrollment — begin enroll first")))
                .flatMap(row -> enableTotpAndIssueRecovery(ownerSubject, passcode, row));
    }

    /** Verify the in-progress TOTP code, enable the factor, and issue fresh recovery codes. */
    private Mono<List<String>> enableTotpAndIssueRecovery(String ownerSubject, String passcode,
                                                           MfaFactorRow row) {
        String secret = cipher.decrypt(row.totpSecretEnc());
        long step = totp.verify(secret,
                row.lastCounter() == null ? -1L : row.lastCounter(), passcode);
        if (step < 0) {
            return Mono.error(ApiException.unauthorized("TOTP code did not verify"));
        }
        // Enable the factor + stamp the accepted step, then (re)issue recovery codes.
        return factors.enableTotp(row.id(), ownerSubject, step)
                .then(regenerateRecoveryCodesInternal(ownerSubject));
    }

    // ── recovery codes ─────────────────────────────────────────────────────────────────

    /** Regenerate the recovery-code set (invalidates the prior set); returns the new
     *  plaintext codes ONCE. STEP-UP gated at the controller. */
    public Mono<List<String>> regenerateRecoveryCodes(String ownerSubject) {
        if (!recovery.isAvailable()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "MFA factor key not provisioned — recovery codes unavailable"));
        }
        return regenerateRecoveryCodesInternal(ownerSubject);
    }

    private Mono<List<String>> regenerateRecoveryCodesInternal(String ownerSubject) {
        List<String> codes = recovery.generateCodes();
        // Invalidate the prior set, then insert each fresh code (only its salted hash, never the
        // plaintext) with a DB-generated id (gen_random_uuid() DEFAULT via RETURNING id). The
        // concatMap preserves the prior saveAll's behavior: delete-then-insert the whole set.
        return recoveryCodes.deleteByOwner(ownerSubject)
                .thenMany(Flux.fromIterable(codes)
                        .concatMap(code -> recoveryCodes.insertReturningId(
                                ownerSubject, recovery.hash(code), false, Instant.now())))
                .then(Mono.just(codes));
    }

    // ── WebAuthn enroll ─────────────────────────────────────────────────────────────────

    /** Issue a registration challenge bound to the session (stored pending). Returns the
     *  options the client passes to navigator.credentials.create(). */
    public Mono<WebAuthnOptions> beginWebAuthnEnroll(String sessionToken) {
        String challenge = webauthn.newChallengeBase64Url();
        return challenges.put(sessionToken, WebAuthnChallengeStore.PURPOSE_REGISTER, challenge)
                .thenReturn(new WebAuthnOptions(challenge, webauthn.rpId(), webauthn.rpName()));
    }

    /** Verify a registration attestation against the session's pending challenge + RP/origin,
     *  reject a dup credentialId, and store the credential + a mirror enabled WEBAUTHN factor
     *  row. The WebAuthn verify is blocking -> boundedElastic. */
    public Mono<String> verifyWebAuthnEnroll(String ownerSubject, String sessionToken,
                                             String attestationResponseJson) {
        return challenges.consume(sessionToken, WebAuthnChallengeStore.PURPOSE_REGISTER)
                .switchIfEmpty(Mono.error(ApiException.badRequest(
                        "no pending WebAuthn registration challenge (expired or not started)")))
                .flatMap(challenge -> Mono.fromCallable(() ->
                                webauthn.verifyRegistration(attestationResponseJson, challenge))
                        .subscribeOn(Schedulers.boundedElastic())
                        .onErrorMap(WebAuthnService.WebAuthnException.class,
                                e -> ApiException.unauthorized("WebAuthn registration did not verify"))
                        .flatMap(cred -> webauthnCredentials.findByCredentialId(cred.credentialIdBase64Url())
                                .flatMap(existing -> Mono.<String>error(ApiException.conflict(
                                        "WebAuthn credential already registered")))
                                .switchIfEmpty(Mono.defer(() -> storeWebAuthnCredential(ownerSubject, cred)))));
    }

    private Mono<String> storeWebAuthnCredential(String ownerSubject,
                                                 WebAuthnService.RegisteredCredential cred) {
        Instant now = Instant.now();
        // Insert the credential (DB-generated id; its id is not surfaced) ...
        return webauthnCredentials.insertReturningId(ownerSubject,
                        cred.credentialIdBase64Url(), cred.attestationCborBase64(),
                        cred.signCount(), cred.transports(), true, now)
                // ... then mirror an ENABLED WEBAUTHN factor row so the unified factor list +
                // verifier see it, and return the DB-generated factor id (unchanged contract).
                .then(factors.insertReturningId(ownerSubject, MfaFactorRow.TYPE_WEBAUTHN,
                        null, null, true, now));
    }

    /** Issue an ASSERTION challenge (challenge-time), bound to the caller's SUBJECT (stored
     *  pending); consumed by the existing POST /bff/mfa/challenge verifier, which has the
     *  subject (from the JWT) but not necessarily the same session token. Keyed on subject so
     *  the challenge survives the challenge POST regardless of cookie/Bearer carrier. */
    public Mono<WebAuthnOptions> beginWebAuthnAssertion(String subject) {
        String challenge = webauthn.newChallengeBase64Url();
        return challenges.put(subject, WebAuthnChallengeStore.PURPOSE_ASSERT, challenge)
                .thenReturn(new WebAuthnOptions(challenge, webauthn.rpId(), webauthn.rpName()));
    }

    // ── list / remove ───────────────────────────────────────────────────────────────────

    /** The caller's enrolled factors (type + enabled + createdAt; NEVER any secret). */
    public Flux<FactorSummary> listFactors(String ownerSubject) {
        return factors.findByOwnerSubject(ownerSubject)
                .map(f -> new FactorSummary(f.id(), f.type(), f.enabled(), f.createdAt()));
    }

    /** Remove the caller's factor by id (owner-scoped). STEP-UP gated at the controller. Also
     *  prunes the backing WebAuthn credential rows when the factor is the last WEBAUTHN one. */
    public Mono<Boolean> removeFactor(String ownerSubject, String factorId) {
        return factors.findById(factorId)
                // OWNER GUARD: a factor owned by another subject is treated as not found.
                .filter(f -> ownerSubject.equals(f.ownerSubject()))
                .switchIfEmpty(Mono.error(ApiException.notFound("no such factor")))
                .flatMap(f -> factors.deleteByIdAndOwner(factorId, ownerSubject)
                        .flatMap(rows -> onFactorDeleted(ownerSubject, f, rows)));
    }

    /** After the delete: prune orphaned WebAuthn credentials or return the delete outcome. */
    private Mono<Boolean> onFactorDeleted(String ownerSubject, MfaFactorRow f, Long rows) {
        if (rows == null || rows == 0L) {
            return Mono.just(false);
        }
        // If that was the last WEBAUTHN factor, prune the credential rows.
        if (MfaFactorRow.TYPE_WEBAUTHN.equals(f.type())) {
            return pruneWebAuthnIfNone(ownerSubject).thenReturn(true);
        }
        return Mono.just(true);
    }

    private Mono<Void> pruneWebAuthnIfNone(String ownerSubject) {
        return factors.findByOwnerSubjectAndType(ownerSubject, MfaFactorRow.TYPE_WEBAUTHN)
                .hasElements()
                .flatMap(stillHas -> {
                    if (Boolean.TRUE.equals(stillHas)) {
                        return Mono.empty();
                    }
                    return webauthnCredentials.findByOwnerSubject(ownerSubject)
                            .flatMap(webauthnCredentials::delete)
                            .then();
                });
    }

    // ── result DTOs (no secrets in any list/get shape) ─────────────────────────────────

    /** TOTP begin-enroll result: the otpauth URI + the base32 secret, shown ONCE for the QR. */
    public record TotpEnrollResult(String factorId, String otpauthUri, String secret) {
    }

    /** WebAuthn ceremony options the client feeds to the WebAuthn API. */
    public record WebAuthnOptions(String challenge, String rpId, String rpName) {
    }

    /** A factor list entry — type + enabled + createdAt only, NEVER a secret. */
    public record FactorSummary(String id, String type, boolean enabled, Instant createdAt) {
    }
}

package net.hugmesh.authcore.mfa;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.casdoor.MfaFactorVerifier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The {@code @Primary} REAL {@link MfaFactorVerifier}. The repositories + the (blocking)
 * {@link WebAuthnService} + the challenge store are mocked; the CRYPTO collaborators
 * ({@link TotpService}, {@link RecoveryCodeService}, {@link MfaSecretCipher}) are REAL so a
 * "verified" outcome has to survive genuine TOTP/HMAC/AES-GCM, not a stubbed boolean.
 *
 * <p>What is proven here:
 * <ul>
 *   <li>TOTP — a genuine current-step code satisfies and ADVANCES the replay floor to the
 *       matched step; a code whose step is at/below the stored floor is a REPLAY and never
 *       reaches the UPDATE; and the CONCURRENT-replay LOSER (the {@code last_counter &lt;
 *       :counter} SQL guard flipping 0 rows) resolves {@code false}.</li>
 *   <li>RECOVERY — a matching UNUSED code is consumed ONE-TIME via the CAS; a CAS that flips
 *       0 rows (concurrent double-spend) resolves {@code false}; a non-matching code never
 *       calls consume.</li>
 *   <li>WEBAUTHN — the OWNER GUARD: a credential belonging to ANOTHER subject is REJECTED and
 *       the assertion is never even verified; a disabled credential is rejected too.</li>
 *   <li>The never-throws / {@code onErrorResume -> false} FAIL-CLOSED contract on every leg.</li>
 * </ul>
 */
class BffStoredMfaFactorVerifierTest {

    /** A deterministic 32-byte test key (same shape the cipher/recovery service expect). */
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private final MfaFactorR2dbcRepository factors = mock(MfaFactorR2dbcRepository.class);
    private final MfaRecoveryCodeR2dbcRepository recoveryCodes =
            mock(MfaRecoveryCodeR2dbcRepository.class);
    private final WebAuthnCredentialR2dbcRepository credentials =
            mock(WebAuthnCredentialR2dbcRepository.class);
    private final WebAuthnChallengeStore challenges = mock(WebAuthnChallengeStore.class);
    private final WebAuthnService webauthn = mock(WebAuthnService.class);

    // REAL crypto — a pass must survive actual TOTP/HMAC/AES-GCM.
    private final MfaSecretCipher cipher = new MfaSecretCipher(KEY);
    private final TotpService totp = new TotpService("HugMesh");
    private final RecoveryCodeService recovery = new RecoveryCodeService(KEY);

    private final BffStoredMfaFactorVerifier verifier = new BffStoredMfaFactorVerifier(
            factors, recoveryCodes, credentials, cipher, totp, recovery, webauthn, challenges);

    // ── helpers ─────────────────────────────────────────────────────────────────────────

    /** Independently reproduce the RFC-4226 truncation so the test does not mirror the impl. */
    private static String codeFor(String base32Secret, long step) {
        try {
            byte[] key = TotpService.base32Decode(base32Secret);
            byte[] msg = new byte[8];
            long v = step;
            for (int i = 7; i >= 0; i--) {
                msg[i] = (byte) (v & 0xff);
                v >>>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(msg);
            int off = h[h.length - 1] & 0x0f;
            int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16)
                    | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private MfaFactorRow totpRow(String id, String owner, String base32Secret, Long floor,
                                 boolean enabled) {
        return new MfaFactorRow(id, owner, MfaFactorRow.TYPE_TOTP, cipher.encrypt(base32Secret),
                floor, enabled, Instant.now());
    }

    private static MfaRecoveryCodeRow codeRow(String id, String owner, String hash, boolean used) {
        return new MfaRecoveryCodeRow(id, owner, hash, used, Instant.now());
    }

    private static WebAuthnCredentialRow credRow(String id, String owner, String credentialId,
                                                 long signCount, boolean enabled) {
        return new WebAuthnCredentialRow(id, owner, credentialId, "att-cbor-b64", signCount,
                null, enabled, Instant.now());
    }

    private boolean satisfied(MfaFactorVerifier.Factor factor, String credential) {
        return Boolean.TRUE.equals(
                verifier.verify("sub-alice", "alice", factor, credential).block());
    }

    // ── input guards ─────────────────────────────────────────────────────────────────────

    @Test
    void nullOrBlankInputs_failClosed_withoutTouchingAnyStore() {
        assertThat(verifier.verify(null, "alice", MfaFactorVerifier.Factor.TOTP, "123456").block())
                .isFalse();
        assertThat(verifier.verify("  ", "alice", MfaFactorVerifier.Factor.TOTP, "123456").block())
                .isFalse();
        assertThat(verifier.verify("sub-alice", "alice", null, "123456").block()).isFalse();
        assertThat(verifier.verify("sub-alice", "alice", MfaFactorVerifier.Factor.TOTP, null)
                .block()).isFalse();
        verifyNoInteractions(factors, recoveryCodes, credentials, challenges, webauthn);
    }

    // ── TOTP ─────────────────────────────────────────────────────────────────────────────

    @Test
    void totp_genuineCode_satisfies_andAdvancesReplayFloorToMatchedStep() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, null, true)));
        when(factors.advanceCounter(anyString(), anyString(), anyLong())).thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step))).isTrue();

        ArgumentCaptor<Long> advanced = ArgumentCaptor.forClass(Long.class);
        verify(factors).advanceCounter(org.mockito.ArgumentMatchers.eq("f1"),
                org.mockito.ArgumentMatchers.eq("sub-alice"), advanced.capture());
        // The replay floor is advanced to EXACTLY the accepted step (not a fixed constant).
        assertThat(advanced.getValue()).isEqualTo(step);
    }

    @Test
    void totp_replayOfAStepAtOrBelowTheStoredFloor_isRejected_andNeverUpdates() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        // Stored floor is ALREADY the current step — the same code is a replay.
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, step, true)));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step))).isFalse();
        verify(factors, never()).advanceCounter(anyString(), anyString(), anyLong());
    }

    @Test
    void totp_concurrentReplayLoser_zeroRowsAdvanced_isNotSatisfied() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, null, true)));
        // The other racer won the (last_counter < :counter) CAS first -> this one updates 0 rows.
        when(factors.advanceCounter(anyString(), anyString(), anyLong())).thenReturn(Mono.just(0L));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step))).isFalse();
        verify(factors).advanceCounter("f1", "sub-alice", step);
    }

    @Test
    void totp_nullRowsFromAdvance_isNotSatisfied() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, null, true)));
        // A driver that reports no update count at all must not be read as success.
        when(factors.advanceCounter(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step))).isFalse();
    }

    @Test
    void totp_disabledFactor_neverSatisfies() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, null, false)));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step))).isFalse();
        verify(factors, never()).advanceCounter(anyString(), anyString(), anyLong());
    }

    @Test
    void totp_undecryptableSecret_failsClosed() {
        // A blob the configured key cannot open (wrong key / tampered) -> decrypt() null.
        MfaFactorRow row = new MfaFactorRow("f1", "sub-alice", MfaFactorRow.TYPE_TOTP,
                Base64.getEncoder().encodeToString(new byte[64]), null, true, Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(row));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, "123456")).isFalse();
        verify(factors, never()).advanceCounter(anyString(), anyString(), anyLong());
    }

    @Test
    void totp_scansPastANonMatchingEnabledRow_andStillSatisfiesOnTheSecond() {
        String other = totp.newSecret();
        String mine = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f-other", "sub-alice", other, null, true),
                        totpRow("f-mine", "sub-alice", mine, null, true)));
        when(factors.advanceCounter(anyString(), anyString(), anyLong())).thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(mine, step))).isTrue();
        verify(factors).advanceCounter("f-mine", "sub-alice", step);
        verify(factors, never()).advanceCounter(
                org.mockito.ArgumentMatchers.eq("f-other"), anyString(), anyLong());
    }

    @Test
    void totp_storeError_failsClosed_neverThrows() {
        when(factors.findByOwnerSubjectAndType(anyString(), anyString()))
                .thenReturn(Flux.error(new IllegalStateException("r2dbc pool exhausted")));
        StepVerifier.create(verifier.verify("sub-alice", "alice",
                        MfaFactorVerifier.Factor.TOTP, "123456"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void totp_noFactorRows_failsClosed() {
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.empty());
        assertThat(satisfied(MfaFactorVerifier.Factor.TOTP, "123456")).isFalse();
    }

    // ── recovery codes ───────────────────────────────────────────────────────────────────

    @Test
    void recovery_matchingUnusedCode_isConsumedOneTime() {
        String code = "ABCD-EFGH-IJKL-MNOP";
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice"))
                .thenReturn(Flux.just(codeRow("r1", "sub-alice", recovery.hash(code), false)));
        when(recoveryCodes.consume("r1", "sub-alice")).thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.RECOVERY, code)).isTrue();
        verify(recoveryCodes).consume("r1", "sub-alice");
    }

    @Test
    void recovery_consumeCasLoser_zeroRows_isNotSatisfied() {
        String code = "ABCD-EFGH-IJKL-MNOP";
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice"))
                .thenReturn(Flux.just(codeRow("r1", "sub-alice", recovery.hash(code), false)));
        // Concurrent double-spend: the other racer flipped used=true first -> 0 rows here.
        when(recoveryCodes.consume("r1", "sub-alice")).thenReturn(Mono.just(0L));

        assertThat(satisfied(MfaFactorVerifier.Factor.RECOVERY, code)).isFalse();
    }

    @Test
    void recovery_nonMatchingCode_isRejected_andNeverConsumes() {
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice"))
                .thenReturn(Flux.just(codeRow("r1", "sub-alice",
                        recovery.hash("ABCD-EFGH-IJKL-MNOP"), false)));

        assertThat(satisfied(MfaFactorVerifier.Factor.RECOVERY, "ZZZZ-ZZZZ-ZZZZ-ZZZZ")).isFalse();
        verify(recoveryCodes, never()).consume(anyString(), anyString());
    }

    @Test
    void recovery_matchIsFormatTolerant_butConsumesTheOwnersRow() {
        // Stored hash is of the formatted code; the caller may present it unformatted/lowercase.
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice"))
                .thenReturn(Flux.just(codeRow("r1", "sub-alice",
                        recovery.hash("ABCD-EFGH-IJKL-MNOP"), false)));
        when(recoveryCodes.consume("r1", "sub-alice")).thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.RECOVERY, "abcdefghijklmnop")).isTrue();
        verify(recoveryCodes).consume("r1", "sub-alice");
    }

    @Test
    void recovery_noUnusedCodes_failsClosed() {
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice")).thenReturn(Flux.empty());
        assertThat(satisfied(MfaFactorVerifier.Factor.RECOVERY, "ABCD-EFGH-IJKL-MNOP")).isFalse();
    }

    @Test
    void recovery_storeError_failsClosed_neverThrows() {
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse(anyString()))
                .thenReturn(Flux.error(new IllegalStateException("boom")));
        StepVerifier.create(verifier.verify("sub-alice", "alice",
                        MfaFactorVerifier.Factor.RECOVERY, "ABCD-EFGH-IJKL-MNOP"))
                .expectNext(false).verifyComplete();
    }

    // ── WebAuthn ─────────────────────────────────────────────────────────────────────────

    @Test
    void webauthn_credentialOwnedByAnotherSubject_isRejected_andNeverVerified() {
        // THE OWNER GUARD. sub-alice presents an assertion for a credential row whose
        // owner_subject is sub-bob: it must NOT satisfy, and the signature must not even be
        // checked (so a valid Bob assertion replayed by Alice can never pass).
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-bob");
        when(credentials.findByCredentialId("cred-bob"))
                .thenReturn(Mono.just(credRow("c1", "sub-bob", "cred-bob", 7L, true)));
        // Everything DOWNSTREAM of the guard is stubbed to SUCCEED — so the only thing that can
        // keep this false is the owner guard itself (drop the guard and the verdict flips true).
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(9L);
        when(credentials.advanceSignCount(anyString(), anyString(), anyLong()))
                .thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-bob\"}")).isFalse();
        verify(webauthn, never()).verifyAssertion(anyString(), anyString(), anyString(), anyLong());
        verify(credentials, never()).advanceSignCount(anyString(), anyString(), anyLong());
    }

    @Test
    void webauthn_disabledCredential_isRejected_andNeverVerified() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, false)));

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isFalse();
        verify(webauthn, never()).verifyAssertion(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void webauthn_ownCredential_verifiedAssertion_advancesSignCount() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, true)));
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(9L);
        when(credentials.advanceSignCount("c1", "sub-alice", 9L)).thenReturn(Mono.just(1L));

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isTrue();
        // The stored floor + the ISSUED challenge are what the ceremony verifies against.
        verify(webauthn).verifyAssertion("{\"rawId\":\"cred-a\"}", "chal-b64", "att-cbor-b64", 7L);
        verify(credentials).advanceSignCount("c1", "sub-alice", 9L);
    }

    @Test
    void webauthn_cloneBackstop_zeroRowsAdvanced_isNotSatisfied() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, true)));
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(9L);
        // Another racer already advanced past 9 -> the (sign_count < :newCount) guard flips 0.
        when(credentials.advanceSignCount("c1", "sub-alice", 9L)).thenReturn(Mono.just(0L));

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isFalse();
    }

    @Test
    void webauthn_nonAdvancingCounterOnANonZeroStoredCount_isNotSatisfied() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, true)));
        // Same counter as stored, and stored != 0 -> not the genuine always-0 authenticator.
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(7L);

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isFalse();
        verify(credentials, never()).advanceSignCount(anyString(), anyString(), anyLong());
    }

    @Test
    void webauthn_genuineAlwaysZeroCounterAuthenticator_isAccepted_withoutAnAdvance() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 0L, true)));
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(0L);

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isTrue();
        verify(credentials, never()).advanceSignCount(anyString(), anyString(), anyLong());
    }

    @Test
    void webauthn_noPendingAssertionChallenge_failsClosed_withoutParsingTheAssertion() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.empty());

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isFalse();
        verifyNoInteractions(webauthn);
        verifyNoInteractions(credentials);
    }

    @Test
    void webauthn_consumesTheAssertChallenge_neverTheRegisterOne() {
        when(challenges.consume(anyString(), anyString())).thenReturn(Mono.empty());
        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}")).isFalse();
        verify(challenges).consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT);
        verify(challenges, never()).consume(
                anyString(), org.mockito.ArgumentMatchers.eq(WebAuthnChallengeStore.PURPOSE_REGISTER));
    }

    @Test
    void webauthn_unparseableAssertion_noCredentialId_failsClosed() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn(null);

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "not-json")).isFalse();
        verifyNoInteractions(credentials);
    }

    @Test
    void webauthn_unknownCredentialId_failsClosed() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-ghost");
        when(credentials.findByCredentialId("cred-ghost")).thenReturn(Mono.empty());

        assertThat(satisfied(MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-ghost\"}")).isFalse();
        verify(webauthn, never()).verifyAssertion(anyString(), anyString(), anyString(), anyLong());
    }

    /**
     * NOTE for anyone touching the two fail-closed layers: this contract is protected TWICE — by
     * the inner {@code onErrorResume(WebAuthnException.class, ...)} at
     * BffStoredMfaFactorVerifier.java:155-156 AND by the outer {@code onErrorResume} in
     * {@code verify()} at :81-84. Deleting EITHER one alone leaves this test green (verified by
     * mutation); only removing both breaks it. The inner handler is therefore redundant
     * defence-in-depth, not dead code to be "cleaned up" on the strength of coverage.
     */
    @Test
    void webauthn_ceremonyRejection_isFailClosedFalse_notAnError() {
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, true)));
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenThrow(new WebAuthnService.WebAuthnException("bad signature"));

        StepVerifier.create(verifier.verify("sub-alice", "alice",
                        MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}"))
                .expectNext(false).verifyComplete();
        verify(credentials, never()).advanceSignCount(anyString(), anyString(), anyLong());
    }

    @Test
    void webauthn_unexpectedRuntimeExceptionFromTheCeremony_stillFailsClosed_neverThrows() {
        // Not a WebAuthnException — the verifier's outer onErrorResume is the last line of defence.
        when(challenges.consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.credentialIdOfAssertion(anyString())).thenReturn("cred-a");
        when(credentials.findByCredentialId("cred-a"))
                .thenReturn(Mono.just(credRow("c1", "sub-alice", "cred-a", 7L, true)));
        when(webauthn.verifyAssertion(anyString(), anyString(), anyString(), anyLong()))
                .thenThrow(new IllegalStateException("webauthn4j blew up"));

        StepVerifier.create(verifier.verify("sub-alice", "alice",
                        MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void webauthn_challengeStoreError_failsClosed_neverThrows() {
        when(challenges.consume(anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("db down")));
        StepVerifier.create(verifier.verify("sub-alice", "alice",
                        MfaFactorVerifier.Factor.WEBAUTHN, "{\"rawId\":\"cred-a\"}"))
                .expectNext(false).verifyComplete();
    }

    // ── the owner is the JWT subject, never a body field ─────────────────────────────────

    @Test
    void everyLegScopesItsLookupToTheCallerSubject() {
        when(factors.findByOwnerSubjectAndType(anyString(), anyString())).thenReturn(Flux.empty());
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse(anyString())).thenReturn(Flux.empty());
        when(challenges.consume(anyString(), anyString())).thenReturn(Mono.empty());

        verifier.verify("sub-alice", "alice", MfaFactorVerifier.Factor.TOTP, "123456").block();
        verifier.verify("sub-alice", "alice", MfaFactorVerifier.Factor.RECOVERY, "X").block();
        verifier.verify("sub-alice", "alice", MfaFactorVerifier.Factor.WEBAUTHN, "{}").block();

        verify(factors).findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP);
        verify(recoveryCodes).findByOwnerSubjectAndUsedFalse("sub-alice");
        verify(challenges).consume("sub-alice", WebAuthnChallengeStore.PURPOSE_ASSERT);
        // The `username` argument is advisory only — it is never used as an owner key.
        verify(factors, never()).findByOwnerSubjectAndType(
                org.mockito.ArgumentMatchers.eq("alice"), anyString());
        verify(recoveryCodes, never()).findByOwnerSubjectAndUsedFalse("alice");
    }

    @Test
    void verifyNeverThrows_forEveryFactor_whenEveryCollaboratorErrors() {
        when(factors.findByOwnerSubjectAndType(anyString(), anyString()))
                .thenReturn(Flux.error(new RuntimeException("x")));
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse(anyString()))
                .thenReturn(Flux.error(new RuntimeException("x")));
        when(challenges.consume(anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("x")));

        for (MfaFactorVerifier.Factor f : MfaFactorVerifier.Factor.values()) {
            StepVerifier.create(verifier.verify("sub-alice", "alice", f, "credential"))
                    .expectNext(false).verifyComplete();
        }
    }

    @Test
    void webauthnService_isNeverAskedToVerifyAnythingOnTheTotpOrRecoveryLegs() {
        String secret = totp.newSecret();
        long step = totp.currentCounter(Instant.now());
        when(factors.findByOwnerSubjectAndType("sub-alice", MfaFactorRow.TYPE_TOTP))
                .thenReturn(Flux.just(totpRow("f1", "sub-alice", secret, null, true)));
        when(factors.advanceCounter(anyString(), anyString(), anyLong())).thenReturn(Mono.just(1L));
        when(recoveryCodes.findByOwnerSubjectAndUsedFalse("sub-alice")).thenReturn(Flux.empty());

        satisfied(MfaFactorVerifier.Factor.TOTP, codeFor(secret, step));
        satisfied(MfaFactorVerifier.Factor.RECOVERY, "ABCD-EFGH-IJKL-MNOP");

        verifyNoInteractions(webauthn);
        verifyNoInteractions(challenges);
        verify(credentials, never()).findByCredentialId(any());
    }
}

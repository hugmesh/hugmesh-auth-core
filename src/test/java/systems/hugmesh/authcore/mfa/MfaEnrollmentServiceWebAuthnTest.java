package systems.hugmesh.authcore.mfa;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The WebAuthn ENROLLMENT orchestration in {@link MfaEnrollmentService} — the leg that owns the
 * DUPLICATE-credentialId guard (the ceremony itself is proven in {@link WebAuthnServiceTest}
 * against a real software authenticator, so {@link WebAuthnService} is mocked here).
 *
 * <p>The dup guard lives at {@code MfaEnrollmentService.java:167-170}, not in
 * {@code WebAuthnService}: registration verifies first, and only then is the resulting
 * credentialId checked against {@code webauthn_credential} — a hit is a 409 and NOTHING is
 * written. Without it a second enrollment of the same authenticator would insert a second
 * credential row (and a second mirror factor row) for the same credentialId, and the verifier's
 * {@code findByCredentialId} lookup — which expects at most one row — would start resolving
 * arbitrarily between them.
 */
class MfaEnrollmentServiceWebAuthnTest {

    private static final String OWNER = "sub-alice";
    private static final String SESSION = "session-token-abc";
    private static final String CRED_ID = "cred-id-b64url";
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private final MfaFactorR2dbcRepository factors = mock(MfaFactorR2dbcRepository.class);
    private final MfaRecoveryCodeR2dbcRepository recoveryCodes =
            mock(MfaRecoveryCodeR2dbcRepository.class);
    private final WebAuthnCredentialR2dbcRepository credentials =
            mock(WebAuthnCredentialR2dbcRepository.class);
    private final WebAuthnService webauthn = mock(WebAuthnService.class);
    private final WebAuthnChallengeStore challenges = mock(WebAuthnChallengeStore.class);

    private final MfaEnrollmentService service = new MfaEnrollmentService(
            factors, recoveryCodes, credentials, new MfaSecretCipher(KEY),
            new TotpService("HugMesh"), new RecoveryCodeService(KEY), webauthn, challenges);

    private static final WebAuthnService.RegisteredCredential VERIFIED =
            new WebAuthnService.RegisteredCredential(CRED_ID, "att-cbor-b64", 0L, "usb,nfc");

    private static WebAuthnCredentialRow existingRow(String owner) {
        return new WebAuthnCredentialRow("c1", owner, CRED_ID, "att-cbor-b64", 3L, null, true,
                Instant.now());
    }

    /** Assert the failure is an ApiException carrying exactly this HTTP status. */
    private static void expectStatus(Mono<?> mono, HttpStatus status) {
        StepVerifier.create(mono)
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(status);
                })
                .verify();
    }

    // ── the duplicate-credentialId guard ─────────────────────────────────────────────────

    @Test
    void verifyEnroll_duplicateCredentialId_is409_andWritesNothing() {
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.verifyRegistration(anyString(), anyString())).thenReturn(VERIFIED);
        // The authenticator is ALREADY enrolled (by this same owner).
        when(credentials.findByCredentialId(CRED_ID)).thenReturn(Mono.just(existingRow(OWNER)));

        expectStatus(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"),
                HttpStatus.CONFLICT);

        verify(credentials, never()).insertReturningId(anyString(), anyString(), anyString(),
                anyLong(), any(), anyBoolean(), any());
        verify(factors, never()).insertReturningId(anyString(), anyString(), any(), any(),
                anyBoolean(), any());
    }

    @Test
    void verifyEnroll_credentialAlreadyOwnedByANOTHERSubject_isAlso409_andNeverRebinds() {
        // The dangerous variant: the credential exists under a DIFFERENT owner. It must not be
        // silently re-registered to the caller (that would give two subjects one authenticator).
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.verifyRegistration(anyString(), anyString())).thenReturn(VERIFIED);
        when(credentials.findByCredentialId(CRED_ID)).thenReturn(Mono.just(existingRow("sub-bob")));

        expectStatus(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"),
                HttpStatus.CONFLICT);

        verify(credentials, never()).insertReturningId(anyString(), anyString(), anyString(),
                anyLong(), any(), anyBoolean(), any());
    }

    @Test
    void verifyEnroll_freshCredentialId_storesTheCredentialAndAnEnabledMirrorFactor() {
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.verifyRegistration(anyString(), anyString())).thenReturn(VERIFIED);
        when(credentials.findByCredentialId(CRED_ID)).thenReturn(Mono.empty());
        when(credentials.insertReturningId(anyString(), anyString(), anyString(), anyLong(),
                any(), anyBoolean(), any())).thenReturn(Mono.just("new-cred-row-id"));
        when(factors.insertReturningId(anyString(), anyString(), any(), any(), anyBoolean(), any()))
                .thenReturn(Mono.just("new-factor-id"));

        StepVerifier.create(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"))
                .expectNext("new-factor-id").verifyComplete();

        // The credential is stored against the AUTHENTICATED owner, enabled, with the verified
        // sign count as its starting monotonic floor.
        verify(credentials).insertReturningId(eq(OWNER), eq(CRED_ID), eq("att-cbor-b64"),
                eq(0L), eq("usb,nfc"), eq(true), any());
        // ...and the mirror WEBAUTHN factor row carries NO secret and is enabled immediately
        // (possession of the authenticator was just proven).
        verify(factors).insertReturningId(eq(OWNER), eq(MfaFactorRow.TYPE_WEBAUTHN),
                eq(null), eq(null), eq(true), any());
    }

    // ── the other fail-closed legs of the same method ─────────────────────────────────────

    @Test
    void verifyEnroll_noPendingRegistrationChallenge_is400_andTheCeremonyNeverRuns() {
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.empty());

        expectStatus(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"),
                HttpStatus.BAD_REQUEST);

        // No client-supplied challenge fallback: without a pending one, nothing is even parsed.
        verify(webauthn, never()).verifyRegistration(anyString(), anyString());
        verify(credentials, never()).findByCredentialId(anyString());
    }

    @Test
    void verifyEnroll_ceremonyRejection_is401_andWritesNothing() {
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.verifyRegistration(anyString(), anyString()))
                .thenThrow(new WebAuthnService.WebAuthnException("bad attestation"));

        expectStatus(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"),
                HttpStatus.UNAUTHORIZED);

        verify(credentials, never()).findByCredentialId(anyString());
        verify(credentials, never()).insertReturningId(anyString(), anyString(), anyString(),
                anyLong(), any(), anyBoolean(), any());
    }

    @Test
    void verifyEnroll_consumesTheREGISTERChallenge_neverTheASSERTOne() {
        // Cross-ceremony confusion guard: an ASSERT challenge must not satisfy a REGISTER verify.
        when(challenges.consume(anyString(), anyString())).thenReturn(Mono.empty());

        expectStatus(service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}"),
                HttpStatus.BAD_REQUEST);

        verify(challenges).consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER);
        verify(challenges, never()).consume(anyString(),
                eq(WebAuthnChallengeStore.PURPOSE_ASSERT));
    }

    @Test
    void verifyEnroll_isKeyedOnTheSESSIONToken_whileTheRowIsKeyedOnTheOWNERSubject() {
        // Registration is session-scoped (the browser tab that called .../options) but what gets
        // persisted is owned by the authenticated subject — the two keys must not be swapped.
        when(challenges.consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER))
                .thenReturn(Mono.just("chal-b64"));
        when(webauthn.verifyRegistration(anyString(), anyString())).thenReturn(VERIFIED);
        when(credentials.findByCredentialId(CRED_ID)).thenReturn(Mono.empty());
        when(credentials.insertReturningId(anyString(), anyString(), anyString(), anyLong(),
                any(), anyBoolean(), any())).thenReturn(Mono.just("row"));
        when(factors.insertReturningId(anyString(), anyString(), any(), any(), anyBoolean(), any()))
                .thenReturn(Mono.just("factor"));

        service.verifyWebAuthnEnroll(OWNER, SESSION, "{\"rawId\":\"x\"}").block();

        verify(challenges).consume(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER);
        verify(challenges, never()).consume(eq(OWNER), anyString());
        verify(credentials).insertReturningId(eq(OWNER), anyString(), anyString(), anyLong(),
                any(), anyBoolean(), any());
        verify(credentials, never()).insertReturningId(eq(SESSION), anyString(), anyString(),
                anyLong(), any(), anyBoolean(), any());
    }

    // ── challenge issuance: the purpose + key each ceremony is bound to ───────────────────

    @Test
    void beginEnroll_stashesAFreshChallengeUnderREGISTER_keyedOnTheSession() {
        when(webauthn.newChallengeBase64Url()).thenReturn("fresh-challenge");
        when(webauthn.rpId()).thenReturn("hugmesh.systems");
        when(webauthn.rpName()).thenReturn("HugMesh");
        when(challenges.put(anyString(), anyString(), anyString())).thenReturn(Mono.empty());

        MfaEnrollmentService.WebAuthnOptions options =
                service.beginWebAuthnEnroll(SESSION).block();

        assertThat(options).isNotNull();
        // The options handed to navigator.credentials.create() carry the SAME challenge that was
        // stashed — if these diverged, no genuine ceremony could ever verify.
        assertThat(options.challenge()).isEqualTo("fresh-challenge");
        assertThat(options.rpId()).isEqualTo("hugmesh.systems");
        assertThat(options.rpName()).isEqualTo("HugMesh");
        verify(challenges).put(SESSION, WebAuthnChallengeStore.PURPOSE_REGISTER, "fresh-challenge");
        verify(challenges, never()).put(anyString(),
                eq(WebAuthnChallengeStore.PURPOSE_ASSERT), anyString());
    }

    @Test
    void beginAssertion_stashesAFreshChallengeUnderASSERT_keyedOnTheSubject() {
        when(webauthn.newChallengeBase64Url()).thenReturn("fresh-assert-challenge");
        when(webauthn.rpId()).thenReturn("hugmesh.systems");
        when(webauthn.rpName()).thenReturn("HugMesh");
        when(challenges.put(anyString(), anyString(), anyString())).thenReturn(Mono.empty());

        MfaEnrollmentService.WebAuthnOptions options =
                service.beginWebAuthnAssertion(OWNER).block();

        assertThat(options).isNotNull();
        assertThat(options.challenge()).isEqualTo("fresh-assert-challenge");
        // Assertion is keyed on the SUBJECT (the verifier only has the JWT sub, not the session).
        verify(challenges).put(OWNER, WebAuthnChallengeStore.PURPOSE_ASSERT,
                "fresh-assert-challenge");
        verify(challenges, never()).put(anyString(),
                eq(WebAuthnChallengeStore.PURPOSE_REGISTER), anyString());
    }
}

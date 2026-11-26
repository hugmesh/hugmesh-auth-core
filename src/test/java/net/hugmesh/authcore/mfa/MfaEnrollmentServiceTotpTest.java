package net.hugmesh.authcore.mfa;

import net.hugmesh.commons.web.ApiException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * TOTP enrolment (2026-11-26): a user tapped "set up" several times, each tap added another
 * pending (disabled) TOTP row, and verify checked the code against the FIRST pending row — not
 * the QR just scanned — so every code failed. Pinned here:
 * <ul>
 *   <li>begin removes the subject's earlier pending TOTP rows (never an enabled one);</li>
 *   <li>verify checks the NEWEST pending row;</li>
 *   <li>a failed code says why: device clock off (with how far) or not from this key;</li>
 *   <li>an unfinished factor is "pending" (removable without step-up).</li>
 * </ul>
 */
class MfaEnrollmentServiceTotpTest {

    private static final String OWNER = "sub-lavender";
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private final MfaFactorR2dbcRepository factors = mock(MfaFactorR2dbcRepository.class);
    private final MfaRecoveryCodeR2dbcRepository recoveryCodes =
            mock(MfaRecoveryCodeR2dbcRepository.class);
    private final MfaSecretCipher cipher = new MfaSecretCipher(KEY);
    private final TotpService totp = new TotpService("HugMesh");

    private final MfaEnrollmentService service = new MfaEnrollmentService(
            factors, recoveryCodes, mock(WebAuthnCredentialR2dbcRepository.class), cipher, totp,
            new RecoveryCodeService(KEY), mock(WebAuthnService.class),
            mock(WebAuthnChallengeStore.class));

    private MfaFactorRow totpRow(String id, boolean enabled, String secret, Instant created) {
        return new MfaFactorRow(id, OWNER, MfaFactorRow.TYPE_TOTP,
                secret == null ? null : cipher.encrypt(secret), null, enabled, created);
    }

    private String codeNow(String secret, int stepOffset) throws Exception {
        var gen = TotpService.class.getDeclaredMethod("generate", byte[].class, long.class);
        gen.setAccessible(true);
        byte[] key = TotpService.base32Decode(secret);
        return (String) gen.invoke(null, key, totp.currentCounter(Instant.now()) + stepOffset);
    }

    @Test
    void begin_removesEarlierPendingRows_butNeverAnEnabledOne() {
        Instant t = Instant.parse("2026-11-26T19:00:00Z");
        when(factors.findByOwnerSubjectAndType(OWNER, MfaFactorRow.TYPE_TOTP)).thenReturn(Flux.just(
                totpRow("old-1", false, totp.newSecret(), t),
                totpRow("old-2", false, totp.newSecret(), t.plusSeconds(60)),
                totpRow("live", true, totp.newSecret(), t.minusSeconds(3600))));
        when(factors.deleteByIdAndOwner(anyString(), eq(OWNER))).thenReturn(Mono.just(1L));
        when(factors.insertReturningId(eq(OWNER), eq(MfaFactorRow.TYPE_TOTP), anyString(),
                isNull(), anyBoolean(), any())).thenReturn(Mono.just("new-id"));

        StepVerifier.create(service.beginTotpEnroll(OWNER, "lavender"))
                .assertNext(r -> assertThat(r.factorId()).isEqualTo("new-id"))
                .verifyComplete();
        verify(factors).deleteByIdAndOwner("old-1", OWNER);
        verify(factors).deleteByIdAndOwner("old-2", OWNER);
        verify(factors, never()).deleteByIdAndOwner("live", OWNER);
    }

    @Test
    void verify_checksTheNewestPendingRow() throws Exception {
        Instant t = Instant.parse("2026-11-26T19:00:00Z");
        String older = totp.newSecret();
        String newest = totp.newSecret();
        when(factors.findByOwnerSubjectAndType(OWNER, MfaFactorRow.TYPE_TOTP)).thenReturn(Flux.just(
                totpRow("older", false, older, t),
                totpRow("newest", false, newest, t.plusSeconds(120))));
        when(factors.enableTotp(eq("newest"), eq(OWNER), anyLong())).thenReturn(Mono.just(1L));
        when(recoveryCodes.deleteByOwner(OWNER)).thenReturn(Mono.just(0L));
        when(recoveryCodes.insertReturningId(eq(OWNER), anyString(), anyBoolean(), any()))
                .thenReturn(Mono.just("rc"));

        StepVerifier.create(service.verifyTotpEnroll(OWNER, codeNow(newest, 0)))
                .assertNext(codes -> assertThat(codes).isNotEmpty())
                .verifyComplete();
        verify(factors).enableTotp(eq("newest"), eq(OWNER), anyLong());
    }

    @Test
    void aCodeFromAnotherKey_saysItIsNotFromTheKeyJustSetUp() throws Exception {
        String pending = totp.newSecret();
        when(factors.findByOwnerSubjectAndType(OWNER, MfaFactorRow.TYPE_TOTP)).thenReturn(Flux.just(
                totpRow("p", false, pending, Instant.now())));
        StepVerifier.create(service.verifyTotpEnroll(OWNER, codeNow(totp.newSecret(), 0)))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(e.getMessage()).contains("not from the key just set up");
                })
                .verify();
    }

    @Test
    void aCodeFromAWrongClock_saysTheClockIsOff_andIsStillRejected() throws Exception {
        String pending = totp.newSecret();
        when(factors.findByOwnerSubjectAndType(OWNER, MfaFactorRow.TYPE_TOTP)).thenReturn(Flux.just(
                totpRow("p", false, pending, Instant.now())));
        StepVerifier.create(service.verifyTotpEnroll(OWNER, codeNow(pending, -6)))  // 3 min behind
                .expectErrorSatisfies(e -> {
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(e.getMessage()).contains("clock").contains("3 minutes behind");
                })
                .verify();
        verify(factors, never()).enableTotp(anyString(), anyString(), anyLong());
    }

    @Test
    void offsetOf_findsSkewInBothDirections_andNothingForAnotherKey() throws Exception {
        String s = totp.newSecret();
        Instant now = Instant.now();
        assertThat(totp.offsetOf(s, codeNow(s, 0), now, 20)).isZero();
        assertThat(totp.offsetOf(s, codeNow(s, 4), now, 20)).isEqualTo(4);
        assertThat(totp.offsetOf(s, codeNow(s, -7), now, 20)).isEqualTo(-7);
        assertThat(totp.offsetOf(s, codeNow(totp.newSecret(), 0), now, 20)).isNull();
        assertThat(totp.offsetOf(s, "12ab56", now, 20)).isNull();
    }

    @Test
    void isPendingFactor_isTrueOnlyForTheCallersOwnDisabledFactor() {
        when(factors.findById("p")).thenReturn(Mono.just(totpRow("p", false, "AAAA", Instant.now())));
        when(factors.findById("e")).thenReturn(Mono.just(totpRow("e", true, "AAAA", Instant.now())));
        when(factors.findById("x")).thenReturn(Mono.empty());
        StepVerifier.create(service.isPendingFactor(OWNER, "p")).expectNext(true).verifyComplete();
        StepVerifier.create(service.isPendingFactor(OWNER, "e")).expectNext(false).verifyComplete();
        StepVerifier.create(service.isPendingFactor("someone-else", "p")).expectNext(false).verifyComplete();
        StepVerifier.create(service.isPendingFactor(OWNER, "x")).expectNext(false).verifyComplete();
    }
}

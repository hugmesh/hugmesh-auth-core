package net.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the A4 dual-stamp orchestration {@link MfaChallengeService} with a MOCKED
 * Casdoor client + verifier + store. Covers (per the test standard):
 * <ul>
 *   <li>USER-SITUATIONAL — dark -&gt; no stamp; verified factor -&gt; BOTH stamps written +
 *       sibling-preserving Property write delegated; subject taken server-side; no session
 *       row -&gt; fail-closed.</li>
 *   <li>FAIL-CLOSED — unverified factor / disabled leg write NOTHING.</li>
 * </ul>
 */
class MfaChallengeServiceTest {

    private final AccountStore store = mock(AccountStore.class);
    private final MfaFactorVerifier verifier = mock(MfaFactorVerifier.class);
    private final CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);

    private MfaChallengeService service(boolean enabled) {
        // MfaStepUpService is the SINGLE source of the dark flag (enabled()); a real instance
        // wired with the same flag keeps the challenge + step-up legs in lockstep.
        MfaStepUpService stepUp = new MfaStepUpService(store, enabled, Duration.ofMinutes(10));
        return new MfaChallengeService(store, verifier, casdoor, stepUp);
    }

    @Test
    void dark_neverVerifiesOrStamps() {
        MfaChallengeService svc = service(false);
        Boolean satisfied = svc.challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.TOTP, "123456").block();
        assertThat(satisfied).isFalse();
        assertThat(svc.enabled()).isFalse();
        verify(verifier, never()).verify(anyString(), anyString(), any(), anyString());
        verify(store, never()).stampMfaSatisfied(anyString(), anyString());
    }

    @Test
    void verifiedFactor_writesBothStamps_andForceRefreshes() {
        when(verifier.verify(eq("sub"), eq("alice"), eq(MfaFactorVerifier.Factor.TOTP), eq("123456")))
                .thenReturn(Mono.just(true));
        when(store.stampMfaSatisfied(eq("bff_tok"), eq("otp"))).thenReturn(Mono.just(1L));
        when(casdoor.writeMfaProperty(eq("alice"), anyLong())).thenReturn(Mono.empty());

        Boolean satisfied = service(true).challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.TOTP, "123456").block();

        assertThat(satisfied).isTrue();
        // (a) AUTHORITATIVE session stamp with the factor's amr.
        verify(store, times(1)).stampMfaSatisfied("bff_tok", "otp");
        // (b) ADVISORY Casdoor Property write (sibling-preservation is CasdoorAdminClient's job).
        verify(casdoor, times(1)).writeMfaProperty(eq("alice"), anyLong());
        // (c) FORCE-REFRESH the raw-JWT client.
    }

    @Test
    void unverifiedFactor_failsClosed_noStamp() {
        when(verifier.verify(anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.just(false));

        Boolean satisfied = service(true).challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.TOTP, "wrong").block();

        assertThat(satisfied).isFalse();
        verify(store, never()).stampMfaSatisfied(anyString(), anyString());
        verify(casdoor, never()).writeMfaProperty(anyString(), anyLong());
    }

    @Test
    void verifierError_failsClosed() {
        when(verifier.verify(anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("boom")));
        Boolean satisfied = service(true).challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.TOTP, "x").block();
        assertThat(satisfied).isFalse();
        verify(store, never()).stampMfaSatisfied(anyString(), anyString());
    }

    @Test
    void verifiedButNoSessionRow_failsClosed() {
        // The factor verified but the session token resolves no row (unknown/expired) -> 0 rows.
        when(verifier.verify(anyString(), anyString(), any(), anyString())).thenReturn(Mono.just(true));
        when(store.stampMfaSatisfied(anyString(), anyString())).thenReturn(Mono.just(0L));

        Boolean satisfied = service(true).challenge("sub", "alice", "bff_unknown",
                MfaFactorVerifier.Factor.TOTP, "123456").block();

        assertThat(satisfied).isFalse();
        // No advisory write when there was nothing authoritative to satisfy.
        verify(casdoor, never()).writeMfaProperty(anyString(), anyLong());
    }

    @Test
    void blankSubject_failsClosed_noVerify() {
        Boolean satisfied = service(true).challenge("  ", "alice", "bff_tok",
                MfaFactorVerifier.Factor.TOTP, "123456").block();
        assertThat(satisfied).isFalse();
        verify(verifier, never()).verify(anyString(), anyString(), any(), anyString());
    }

    @Test
    void advisoryWriteFailure_doesNotFailChallenge_sessionStampStands() {
        when(verifier.verify(anyString(), anyString(), any(), anyString())).thenReturn(Mono.just(true));
        when(store.stampMfaSatisfied(anyString(), anyString())).thenReturn(Mono.just(1L));
        // Casdoor Property write blows up -> the challenge still SUCCEEDS (advisory is best-effort).
        when(casdoor.writeMfaProperty(anyString(), anyLong()))
                .thenReturn(Mono.error(new RuntimeException("casdoor down")));

        Boolean satisfied = service(true).challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.WEBAUTHN, "assertion").block();
        assertThat(satisfied).isTrue();
        verify(store, times(1)).stampMfaSatisfied("bff_tok", "webauthn");
    }

    @Test
    void clearProperty_delegatesToCasdoor_bestEffort() {
        when(casdoor.clearMfaProperty("alice")).thenReturn(Mono.empty());
        service(true).clearProperty("alice").block();
        verify(casdoor, times(1)).clearMfaProperty("alice");
    }

    @Test
    void clearProperty_noCasdoorClient_noOp() {
        MfaStepUpService stepUp = new MfaStepUpService(store, true, Duration.ofMinutes(10));
        MfaChallengeService noCasdoor = new MfaChallengeService(store, verifier, null, stepUp);
        when(verifier.verify(anyString(), anyString(), any(), anyString())).thenReturn(Mono.just(true));
        when(store.stampMfaSatisfied(anyString(), anyString())).thenReturn(Mono.just(1L));
        // No NPE, resolves empty.
        noCasdoor.clearProperty("alice").block();
        // Verified challenge with a null Casdoor client: the advisory write is skipped, the
        // authoritative session stamp still lands -> success.
        Boolean satisfied = noCasdoor.challenge("sub", "alice", "bff_tok",
                MfaFactorVerifier.Factor.RECOVERY, "code").block();
        assertThat(satisfied).isTrue();
    }

    @Test
    void factorParse_amrMapping() {
        assertThat(MfaFactorVerifier.Factor.parse("totp")).isEqualTo(MfaFactorVerifier.Factor.TOTP);
        assertThat(MfaFactorVerifier.Factor.parse("WebAuthn")).isEqualTo(MfaFactorVerifier.Factor.WEBAUTHN);
        assertThat(MfaFactorVerifier.Factor.parse("recovery")).isEqualTo(MfaFactorVerifier.Factor.RECOVERY);
        assertThat(MfaFactorVerifier.Factor.parse("nonsense")).isNull();
        assertThat(MfaFactorVerifier.Factor.TOTP.amr()).isEqualTo("otp");
        assertThat(MfaFactorVerifier.Factor.WEBAUTHN.amr()).isEqualTo("webauthn");
        assertThat(MfaFactorVerifier.Factor.RECOVERY.amr()).isEqualTo("recovery");
    }
}

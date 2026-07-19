package systems.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.authcore.account.AccountStore;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A5 MFA step-up leg — the co-equal, license-INDEPENDENT satisfier. Unit-level (the
 * {@link AccountStore} is mocked): proves the flag gate (off -> never satisfies), the freshness
 * window (fresh stamp satisfies, stale stamp rejected), and the fail-closed branches
 * (never-stamped, no timestamp, unknown token, blank token).
 */
class MfaStepUpServiceTest {

    private final AccountStore store = mock(AccountStore.class);

    private MfaStepUpService enabled(Duration freshness) {
        return new MfaStepUpService(store, true, freshness);
    }

    private MfaStepUpService disabled() {
        return new MfaStepUpService(store, false, Duration.ofMinutes(10));
    }

    @Test
    void flagOff_neverSatisfies_andNeverHitsStore() {
        MfaStepUpService svc = disabled();
        StepVerifier.create(svc.isFresh("bff_token")).expectNext(false).verifyComplete();
        // Fail-fast on the flag: the store is never queried when the leg is disabled.
        verify(store, never()).mfaStateOf(anyString());
        assertThat(svc.enabled()).isFalse();
    }

    @Test
    void freshStamp_satisfies() {
        when(store.mfaStateOf("bff_t")).thenReturn(Mono.just(
                new AccountStore.MfaState(true, LocalDateTime.now().minusMinutes(2))));
        StepVerifier.create(enabled(Duration.ofMinutes(10)).isFresh("bff_t"))
                .expectNext(true).verifyComplete();
    }

    @Test
    void staleStamp_rejected() {
        // satisfied=true but stamped 20m ago, past the 10m window -> NOT fresh.
        when(store.mfaStateOf("bff_t")).thenReturn(Mono.just(
                new AccountStore.MfaState(true, LocalDateTime.now().minusMinutes(20))));
        StepVerifier.create(enabled(Duration.ofMinutes(10)).isFresh("bff_t"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void neverStamped_failsClosed() {
        when(store.mfaStateOf("bff_t")).thenReturn(Mono.just(
                new AccountStore.MfaState(false, null)));
        StepVerifier.create(enabled(Duration.ofMinutes(10)).isFresh("bff_t"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void satisfiedButNoTimestamp_failsClosed() {
        when(store.mfaStateOf("bff_t")).thenReturn(Mono.just(
                new AccountStore.MfaState(true, null)));
        StepVerifier.create(enabled(Duration.ofMinutes(10)).isFresh("bff_t"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void unknownToken_failsClosed() {
        when(store.mfaStateOf("bff_t")).thenReturn(Mono.empty());
        StepVerifier.create(enabled(Duration.ofMinutes(10)).isFresh("bff_t"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void blankOrNullToken_failsClosed_noStore() {
        MfaStepUpService svc = enabled(Duration.ofMinutes(10));
        StepVerifier.create(svc.isFresh(null)).expectNext(false).verifyComplete();
        StepVerifier.create(svc.isFresh("  ")).expectNext(false).verifyComplete();
        verify(store, never()).mfaStateOf(anyString());
    }

    @Test
    void nonPositiveFreshness_degradesToTenMinutes() {
        MfaStepUpService svc = new MfaStepUpService(store, true, Duration.ZERO);
        assertThat(svc.freshness()).isEqualTo(Duration.ofMinutes(10));
        // A 2-minute-old stamp is fresh under the 10m default.
        assertThat(svc.freshSnapshot(new AccountStore.MfaState(true, LocalDateTime.now().minusMinutes(2))))
                .isTrue();
    }

    @Test
    void freshSnapshot_disabledLeg_isFalse() {
        // The snapshot predicate also honours the flag (defence-in-depth).
        assertThat(disabled().freshSnapshot(
                new AccountStore.MfaState(true, LocalDateTime.now()))).isFalse();
    }
}

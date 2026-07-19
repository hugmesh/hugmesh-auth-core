package systems.hugmesh.authcore.account;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-level (the repositories are mocked) cover for the band-180 custody passthroughs on
 * {@link AccountStore}. Proves the {@code bff_}-prefix guard (a non-bff token short-circuits to
 * {@code 0L}/empty WITHOUT touching the repo — fail-closed, no leak to the datastore) and that
 * {@code sessionRow} reuses the {@code sessionOfToken} lazy-reap (expired → delete + empty; live
 * → row intact, custody columns and all).
 */
class AccountStoreCustodyTest {

    private final AllowlistRepository allowlist = mock(AllowlistRepository.class);
    private final AccountRowRepository accounts = mock(AccountRowRepository.class);
    private final BffSessionRepository sessions = mock(BffSessionRepository.class);
    private final NamespaceGrantRepository grants = mock(NamespaceGrantRepository.class);

    private AccountStore store() {
        return new AccountStore(allowlist, accounts, sessions, grants, "admin@hugmesh.systems");
    }

    @Test
    void stampCustody_nonBffToken_returnsZero_andRepoNotCalled() {
        AccountStore store = store();
        StepVerifier.create(store.stampCustody("nope", "a", "r", LocalDateTime.now()))
                .expectNext(0L).verifyComplete();
        StepVerifier.create(store.stampCustody(null, "a", "r", LocalDateTime.now()))
                .expectNext(0L).verifyComplete();
        verify(sessions, never()).stampCustody(anyString(), anyString(), anyString(), any());
    }

    @Test
    void clearCustody_nonBffToken_returnsZero_andRepoNotCalled() {
        AccountStore store = store();
        StepVerifier.create(store.clearCustody("nope")).expectNext(0L).verifyComplete();
        StepVerifier.create(store.clearCustody(null)).expectNext(0L).verifyComplete();
        verify(sessions, never()).clearCustody(anyString());
    }

    @Test
    void stampClearCustody_bffToken_delegatesToRepo() {
        AccountStore store = store();
        LocalDateTime exp = LocalDateTime.now().plusMinutes(5);
        when(sessions.stampCustody("bff_x", "ea", "er", exp)).thenReturn(Mono.just(1L));
        when(sessions.clearCustody("bff_x")).thenReturn(Mono.just(1L));

        StepVerifier.create(store.stampCustody("bff_x", "ea", "er", exp)).expectNext(1L).verifyComplete();
        StepVerifier.create(store.clearCustody("bff_x")).expectNext(1L).verifyComplete();

        verify(sessions).stampCustody("bff_x", "ea", "er", exp);
        verify(sessions).clearCustody("bff_x");
    }

    @Test
    void sessionRow_nonBffToken_empty_andRepoNotCalled() {
        AccountStore store = store();
        StepVerifier.create(store.sessionRow("nope")).verifyComplete();
        StepVerifier.create(store.sessionRow(null)).verifyComplete();
        verify(sessions, never()).findById(anyString());
    }

    @Test
    void sessionRow_liveRow_returnedIntact() {
        AccountStore store = store();
        BffSession live = new BffSession("bff_live", "google:alice",
                LocalDateTime.now(), LocalDateTime.now().plusHours(1),
                false, null, null, "ea", "er", LocalDateTime.now().plusMinutes(5), null);
        when(sessions.findById("bff_live")).thenReturn(Mono.just(live));

        StepVerifier.create(store.sessionRow("bff_live"))
                .expectNextMatches(s -> s.token().equals("bff_live")
                        && "ea".equals(s.accessTokenEnc())
                        && "er".equals(s.refreshTokenEnc()))
                .verifyComplete();
        // A live row is NOT reaped.
        verify(sessions, never()).deleteById(anyString());
    }

    @Test
    void sessionRow_expiredRow_lazyReaped_returnsEmpty() {
        AccountStore store = store();
        BffSession expired = new BffSession("bff_old", "google:alice",
                LocalDateTime.now().minusHours(13), LocalDateTime.now().minusMinutes(1),
                false, null, null, true);
        when(sessions.findById("bff_old")).thenReturn(Mono.just(expired));
        when(sessions.deleteById("bff_old")).thenReturn(Mono.empty());

        StepVerifier.create(store.sessionRow("bff_old")).verifyComplete();
        verify(sessions).deleteById("bff_old");
    }
}

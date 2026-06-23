package systems.snapdragon.authcore.account;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC-H2 data slice for the 2.2.0 "list a user's sessions by account" finders. The
 * SECURITY-CRITICAL property under test is CROSS-ACCOUNT ISOLATION: account A's lookup returns
 * ONLY A's rows and never B's — the foundation of "a user may only ever see/revoke THEIR OWN
 * sessions". Also asserts the live-only finder hides an expired row so a stale, unreaped
 * session never surfaces in the listing.
 */
@DataR2dbcTest
@Import({BffSessionTestDatabaseConfig.class})
class BffSessionByAccountTest {

    @Autowired BffSessionRepository repo;

    /** Start each @Test from an empty table — the @DataR2dbcTest H2 instance is shared
     *  across methods and is NOT auto-reset, so seeds would otherwise accumulate and break
     *  the cross-account isolation row counts. */
    @BeforeEach
    void clean() {
        repo.deleteAll().block();
    }

    /** Also wipe afterwards so rows never leak into other @DataR2dbcTest classes in the module. */
    @AfterEach
    void wipe() {
        repo.deleteAll().block();
    }

    /** Insert a fresh live session for {@code accountId} (isNew=true forces the INSERT). */
    private void seed(String token, String accountId, LocalDateTime created, LocalDateTime expires) {
        repo.save(new BffSession(token, accountId, created, expires,
                false, null, null, true)).block();
    }

    @Test
    void findByAccountId_returnsOnlyThatAccountsRows_crossAccountIsolation() {
        LocalDateTime now = LocalDateTime.now();
        // Two sessions for account A, one for account B — interleaved.
        seed("bff_a1", "google:alice@x.com", now.minusMinutes(2), now.plusHours(12));
        seed("bff_b1", "google:bob@x.com", now.minusMinutes(1), now.plusHours(12));
        seed("bff_a2", "google:alice@x.com", now, now.plusHours(12));

        List<BffSession> aRows =
                repo.findByAccountIdOrderByCreatedAtDesc("google:alice@x.com").collectList().block();

        assertThat(aRows).hasSize(2);
        // Every returned row belongs to A — B's row is never present (the isolation invariant).
        assertThat(aRows).allMatch(r -> r.accountId().equals("google:alice@x.com"));
        assertThat(aRows).extracting(BffSession::token)
                .containsExactly("bff_a2", "bff_a1")   // newest-first ordering
                .doesNotContain("bff_b1");

        // And B's lookup is symmetric: only B's single row.
        StepVerifier.create(repo.findByAccountIdOrderByCreatedAtDesc("google:bob@x.com"))
                .assertNext(r -> assertThat(r.token()).isEqualTo("bff_b1"))
                .verifyComplete();
    }

    @Test
    void findByAccountId_unknownAccount_returnsEmpty() {
        seed("bff_only", "google:alice@x.com", LocalDateTime.now(), LocalDateTime.now().plusHours(12));

        StepVerifier.create(repo.findByAccountIdOrderByCreatedAtDesc("google:nobody@x.com"))
                .verifyComplete();
    }

    @Test
    void findByAccountIdAndExpiresAtAfter_hidesExpiredRows() {
        LocalDateTime now = LocalDateTime.now();
        seed("bff_live", "google:alice@x.com", now, now.plusHours(12));
        seed("bff_dead", "google:alice@x.com", now.minusHours(24), now.minusHours(1)); // already expired

        // Live-only finder with a now() cutoff: the expired row is filtered at the DB.
        StepVerifier.create(
                        repo.findByAccountIdAndExpiresAtAfterOrderByCreatedAtDesc("google:alice@x.com", now))
                .assertNext(r -> assertThat(r.token()).isEqualTo("bff_live"))
                .verifyComplete();
    }
}

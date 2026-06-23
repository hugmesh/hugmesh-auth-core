package systems.snapdragon.authcore.mfa;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.ContextConfiguration;
import reactor.test.StepVerifier;
import systems.snapdragon.authcore.support.PostgresSliceTestConfig;
import systems.snapdragon.authcore.SliceTestApp;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for {@link MfaRecoveryCodeR2dbcRepository} over Testcontainers-Postgres. Proves
 * the DB-generated-UUID-PK INSERT ... RETURNING id round-trips, and that the one-time consume
 * CAS + owner-scoped regenerate-delete preserve their semantics EXACTLY.
 */
@DataR2dbcTest
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@ContextConfiguration(classes = SliceTestApp.class)
@Import(PostgresSliceTestConfig.class)
class MfaRecoveryCodeRepositoryPostgresTest extends PostgresTestSupport {

    @Autowired MfaRecoveryCodeR2dbcRepository repo;

    @Test
    void insertReturningId_mintsDbId_andStoresUnusedHash() {
        String id = repo.insertReturningId("google:alice", "hash-1", false, Instant.now()).block();

        assertThat(id).isNotBlank().hasSize(36);
        MfaRecoveryCodeRow row = repo.findById(id).block();
        assertThat(row.ownerSubject()).isEqualTo("google:alice");
        assertThat(row.codeHash()).isEqualTo("hash-1");
        assertThat(row.used()).isFalse();
    }

    @Test
    void consume_isOneTime_andOwnerScoped() {
        String id = repo.insertReturningId("google:bob", "hash-2", false, Instant.now()).block();

        // Wrong owner → 0 rows.
        StepVerifier.create(repo.consume(id, "google:mallory")).expectNext(0L).verifyComplete();
        // Owner first consume → 1.
        StepVerifier.create(repo.consume(id, "google:bob")).expectNext(1L).verifyComplete();
        // Second (double-spend) → 0 (used predicate).
        StepVerifier.create(repo.consume(id, "google:bob")).expectNext(0L).verifyComplete();
    }

    @Test
    void deleteByOwner_invalidatesOnlyThatOwnersSet() {
        repo.insertReturningId("google:carol", "h-a", false, Instant.now()).block();
        repo.insertReturningId("google:carol", "h-b", false, Instant.now()).block();
        repo.insertReturningId("google:dave", "h-c", false, Instant.now()).block();

        StepVerifier.create(repo.deleteByOwner("google:carol")).expectNext(2L).verifyComplete();

        StepVerifier.create(repo.findByOwnerSubjectAndUsedFalse("google:carol"))
                .verifyComplete();
        StepVerifier.create(repo.findByOwnerSubjectAndUsedFalse("google:dave").count())
                .expectNext(1L).verifyComplete();
    }
}

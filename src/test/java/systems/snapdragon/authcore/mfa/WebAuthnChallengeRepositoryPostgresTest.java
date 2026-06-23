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

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for {@link WebAuthnChallengeR2dbcRepository} over Testcontainers-Postgres.
 * Proves the DB-generated-UUID-PK INSERT ... RETURNING id round-trips, and the atomic
 * single-use consume (unexpired + used=false + owner + ceremony) and the supersede-prune
 * preserve their semantics EXACTLY.
 */
@DataR2dbcTest
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@ContextConfiguration(classes = SliceTestApp.class)
@Import(PostgresSliceTestConfig.class)
class WebAuthnChallengeRepositoryPostgresTest extends PostgresTestSupport {

    @Autowired WebAuthnChallengeR2dbcRepository repo;

    private static final String REGISTER = CeremonyType.REGISTER.value();
    private static final String ASSERT = CeremonyType.ASSERT.value();

    @Test
    void insertReturningId_mintsDbId_andRoundTripsAsPending() {
        Instant now = Instant.now();
        String id = repo.insertReturningId("google:alice", "chal-1", REGISTER,
                now.plus(Duration.ofMinutes(5)), false, now).block();

        assertThat(id).isNotBlank().hasSize(36);
        WebAuthnChallengeRow row = repo.findById(id).block();
        assertThat(row.ownerSubject()).isEqualTo("google:alice");
        assertThat(row.challenge()).isEqualTo("chal-1");
        assertThat(row.ceremonyType()).isEqualTo(REGISTER);
        assertThat(row.used()).isFalse();
    }

    @Test
    void consume_isOneTime_andRejectsExpired_andIsOwnerCeremonyScoped() {
        Instant now = Instant.now();
        String id = repo.insertReturningId("google:bob", "chal-2", REGISTER,
                now.plus(Duration.ofMinutes(5)), false, now).block();

        // Wrong ceremony → 0.
        StepVerifier.create(repo.consume(id, "google:bob", ASSERT, now)).expectNext(0L).verifyComplete();
        // Wrong owner → 0.
        StepVerifier.create(repo.consume(id, "google:mallory", REGISTER, now)).expectNext(0L).verifyComplete();
        // Correct → 1.
        StepVerifier.create(repo.consume(id, "google:bob", REGISTER, now)).expectNext(1L).verifyComplete();
        // Replay → 0 (used predicate).
        StepVerifier.create(repo.consume(id, "google:bob", REGISTER, now)).expectNext(0L).verifyComplete();
    }

    @Test
    void consume_rejectsExpiredRow() {
        Instant now = Instant.now();
        // expires_at already in the past relative to the consume's :now.
        String id = repo.insertReturningId("google:carol", "chal-3", REGISTER,
                now.minus(Duration.ofMinutes(1)), false, now.minus(Duration.ofMinutes(6))).block();

        StepVerifier.create(repo.consume(id, "google:carol", REGISTER, now)).expectNext(0L).verifyComplete();
    }

    @Test
    void pruneOwnerCeremony_clearsOnlyThatOwnerCeremony() {
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofMinutes(5));
        repo.insertReturningId("google:dave", "c1", REGISTER, exp, false, now).block();
        repo.insertReturningId("google:dave", "c2", ASSERT, exp, false, now).block();
        repo.insertReturningId("google:erin", "c3", REGISTER, exp, false, now).block();

        StepVerifier.create(repo.pruneOwnerCeremony("google:dave", REGISTER)).expectNext(1L).verifyComplete();

        // dave's REGISTER gone; dave's ASSERT + erin's REGISTER survive.
        StepVerifier.create(repo.findByOwnerSubjectAndCeremonyTypeAndUsedFalseOrderByCreatedAtDesc(
                "google:dave", REGISTER)).verifyComplete();
        StepVerifier.create(repo.findByOwnerSubjectAndCeremonyTypeAndUsedFalseOrderByCreatedAtDesc(
                "google:dave", ASSERT).count()).expectNext(1L).verifyComplete();
        StepVerifier.create(repo.findByOwnerSubjectAndCeremonyTypeAndUsedFalseOrderByCreatedAtDesc(
                "google:erin", REGISTER).count()).expectNext(1L).verifyComplete();
    }
}

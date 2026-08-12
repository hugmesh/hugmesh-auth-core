package net.hugmesh.authcore.mfa;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.ContextConfiguration;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.support.PostgresSliceTestConfig;
import net.hugmesh.authcore.SliceTestApp;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for {@link MfaFactorR2dbcRepository} over a Testcontainers-Postgres store with
 * the MFA DDL applied (the {@link PostgresSliceTestConfig} pattern). Proves the release-2.3.0
 * DB-GENERATED-UUID-PK INSERT ... RETURNING id round-trips on REAL Postgres
 * ({@code (gen_random_uuid())::text} DEFAULT) — which H2 cannot honour — and that the
 * owner-scoped reads / enable / counter-advance / delete preserve their semantics EXACTLY.
 */
@DataR2dbcTest
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@ContextConfiguration(classes = SliceTestApp.class)
@Import(PostgresSliceTestConfig.class)
class MfaFactorRepositoryPostgresTest extends PostgresTestSupport {

    @Autowired MfaFactorR2dbcRepository repo;

    @Test
    void insertReturningId_mintsDbId_andRoundTripsAsDisabledTotpFactor() {
        String id = repo.insertReturningId("google:alice", MfaFactorRow.TYPE_TOTP, "encSecret",
                null, false, Instant.now()).block();

        // The id is database-minted (UUID-shaped, 36 chars), NOT app-supplied.
        assertThat(id).isNotBlank().hasSize(36);

        MfaFactorRow row = repo.findById(id).block();
        assertThat(row).isNotNull();
        assertThat(row.ownerSubject()).isEqualTo("google:alice");
        assertThat(row.type()).isEqualTo(MfaFactorRow.TYPE_TOTP);
        assertThat(row.totpSecretEnc()).isEqualTo("encSecret");
        assertThat(row.lastCounter()).isNull();
        assertThat(row.enabled()).isFalse();
        assertThat(row.createdAt()).isNotNull();
    }

    @Test
    void enableTotp_isOwnerScoped_andStampsCounter() {
        String id = repo.insertReturningId("google:bob", MfaFactorRow.TYPE_TOTP, "enc",
                null, false, Instant.now()).block();

        // A DIFFERENT subject can NOT flip this factor (0 rows) — cross-user isolation.
        StepVerifier.create(repo.enableTotp(id, "google:mallory", 7L)).expectNext(0L).verifyComplete();
        // The owner can.
        StepVerifier.create(repo.enableTotp(id, "google:bob", 7L)).expectNext(1L).verifyComplete();

        MfaFactorRow after = repo.findById(id).block();
        assertThat(after.enabled()).isTrue();
        assertThat(after.lastCounter()).isEqualTo(7L);
    }

    @Test
    void advanceCounter_rejectsReplayOfSameOrEarlierStep() {
        String id = repo.insertReturningId("google:carol", MfaFactorRow.TYPE_TOTP, "enc",
                null, true, Instant.now()).block();

        StepVerifier.create(repo.advanceCounter(id, "google:carol", 5L)).expectNext(1L).verifyComplete();
        // Same step → 0 rows (replay guard at the SQL predicate).
        StepVerifier.create(repo.advanceCounter(id, "google:carol", 5L)).expectNext(0L).verifyComplete();
        // Earlier step → 0 rows.
        StepVerifier.create(repo.advanceCounter(id, "google:carol", 4L)).expectNext(0L).verifyComplete();
    }

    @Test
    void deleteByIdAndOwner_isOwnerScoped() {
        String id = repo.insertReturningId("google:dave", MfaFactorRow.TYPE_WEBAUTHN, null,
                null, true, Instant.now()).block();

        // Another subject cannot delete it.
        StepVerifier.create(repo.deleteByIdAndOwner(id, "google:eve")).expectNext(0L).verifyComplete();
        assertThat(repo.findById(id).block()).isNotNull();
        // The owner can.
        StepVerifier.create(repo.deleteByIdAndOwner(id, "google:dave")).expectNext(1L).verifyComplete();
        assertThat(repo.findById(id).block()).isNull();
    }
}

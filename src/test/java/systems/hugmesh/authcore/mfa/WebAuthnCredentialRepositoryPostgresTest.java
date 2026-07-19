package systems.hugmesh.authcore.mfa;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.ContextConfiguration;
import reactor.test.StepVerifier;
import systems.hugmesh.authcore.support.PostgresSliceTestConfig;
import systems.hugmesh.authcore.SliceTestApp;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for {@link WebAuthnCredentialR2dbcRepository} over Testcontainers-Postgres.
 * Proves the DB-generated-UUID-PK INSERT ... RETURNING id round-trips, the credentialId
 * lookup backs the dup check, and the monotonic sign-count advance + owner-scoped delete
 * preserve their semantics EXACTLY.
 */
@DataR2dbcTest
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@ContextConfiguration(classes = SliceTestApp.class)
@Import(PostgresSliceTestConfig.class)
class WebAuthnCredentialRepositoryPostgresTest extends PostgresTestSupport {

    @Autowired WebAuthnCredentialR2dbcRepository repo;

    @Test
    void insertReturningId_mintsDbId_andRoundTrips() {
        String id = repo.insertReturningId("google:alice", "credA", "cose", 0L, "usb,nfc",
                true, Instant.now()).block();

        assertThat(id).isNotBlank().hasSize(36);
        WebAuthnCredentialRow row = repo.findById(id).block();
        assertThat(row.ownerSubject()).isEqualTo("google:alice");
        assertThat(row.credentialId()).isEqualTo("credA");
        assertThat(row.publicKeyCose()).isEqualTo("cose");
        assertThat(row.signCount()).isEqualTo(0L);
        assertThat(row.transports()).isEqualTo("usb,nfc");
        assertThat(row.enabled()).isTrue();
    }

    @Test
    void findByCredentialId_backsTheDupCheck() {
        repo.insertReturningId("google:bob", "credB", "cose", 0L, null, true, Instant.now()).block();

        StepVerifier.create(repo.findByCredentialId("credB"))
                .assertNext(r -> assertThat(r.ownerSubject()).isEqualTo("google:bob"))
                .verifyComplete();
        StepVerifier.create(repo.findByCredentialId("nope")).verifyComplete();
    }

    @Test
    void advanceSignCount_isMonotonic_andOwnerScoped() {
        String id = repo.insertReturningId("google:carol", "credC", "cose", 5L, null,
                true, Instant.now()).block();

        // Wrong owner → 0.
        StepVerifier.create(repo.advanceSignCount(id, "google:mallory", 9L)).expectNext(0L).verifyComplete();
        // Strictly greater → 1.
        StepVerifier.create(repo.advanceSignCount(id, "google:carol", 9L)).expectNext(1L).verifyComplete();
        // Equal/lower (clone) → 0.
        StepVerifier.create(repo.advanceSignCount(id, "google:carol", 9L)).expectNext(0L).verifyComplete();
        StepVerifier.create(repo.advanceSignCount(id, "google:carol", 8L)).expectNext(0L).verifyComplete();
    }

    @Test
    void deleteByIdAndOwner_isOwnerScoped() {
        String id = repo.insertReturningId("google:dave", "credD", "cose", 0L, null,
                true, Instant.now()).block();

        StepVerifier.create(repo.deleteByIdAndOwner(id, "google:eve")).expectNext(0L).verifyComplete();
        StepVerifier.create(repo.deleteByIdAndOwner(id, "google:dave")).expectNext(1L).verifyComplete();
        assertThat(repo.findById(id).block()).isNull();
    }
}

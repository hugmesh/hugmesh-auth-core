package systems.snapdragon.authcore.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC-H2 data slice for the {@code bff_session} band-180 custody updaters. Validates the
 * partial-column SQL against H2 (PostgreSQL-compat): {@code stampCustody} round-trips the
 * encrypted token + expiry columns and bumps {@code custody_updated_at}; {@code clearCustody}
 * nulls them; and proves partial-update ISOLATION in BOTH directions — a custody update never
 * touches the MFA columns and an MFA stamp never touches the custody columns.
 */
@DataR2dbcTest
@Import({BffSessionTestDatabaseConfig.class})
class BffSessionRepositoryTest {

    @Autowired BffSessionRepository repo;

    /** Insert a fresh live session (isNew=true forces the INSERT for the assigned-PK record). */
    private BffSession seed(String token) {
        LocalDateTime now = LocalDateTime.now();
        return repo.save(new BffSession(token, "google:alice", now, now.plusHours(12),
                false, null, null, true)).block();
    }

    @Test
    void stampCustody_roundTripsEncAndExpiry_andBumpsCustodyUpdatedAt() {
        seed("bff_stamp1");

        StepVerifier.create(repo.stampCustody("bff_stamp1", "encAccess", "encRefresh",
                        LocalDateTime.of(2030, 1, 1, 0, 0)))
                .expectNext(1L).verifyComplete();

        BffSession after = repo.findById("bff_stamp1").block();
        assertThat(after.accessTokenEnc()).isEqualTo("encAccess");
        assertThat(after.refreshTokenEnc()).isEqualTo("encRefresh");
        assertThat(after.accessTokenExpiresAt()).isEqualTo(LocalDateTime.of(2030, 1, 1, 0, 0));
        assertThat(after.custodyUpdatedAt()).isNotNull();
    }

    @Test
    void stampCustody_unknownToken_returnsZero() {
        StepVerifier.create(repo.stampCustody("bff_nope", "a", "r", LocalDateTime.now()))
                .expectNext(0L).verifyComplete();
    }

    @Test
    void clearCustody_nullsTheEncAndExpiryColumns() {
        seed("bff_clear1");
        repo.stampCustody("bff_clear1", "encAccess", "encRefresh", LocalDateTime.now()).block();

        StepVerifier.create(repo.clearCustody("bff_clear1")).expectNext(1L).verifyComplete();

        BffSession after = repo.findById("bff_clear1").block();
        assertThat(after.accessTokenEnc()).isNull();
        assertThat(after.refreshTokenEnc()).isNull();
        assertThat(after.accessTokenExpiresAt()).isNull();
        // custody_updated_at is still bumped by the clear (audit of WHEN it was cleared).
        assertThat(after.custodyUpdatedAt()).isNotNull();
    }

    @Test
    void custodyUpdate_doesNotTouchMfaColumns() {
        seed("bff_iso1");
        // Stamp an MFA satisfaction first.
        repo.stampMfaSatisfied("bff_iso1", "webauthn").block();

        repo.stampCustody("bff_iso1", "encAccess", "encRefresh", LocalDateTime.now()).block();

        BffSession after = repo.findById("bff_iso1").block();
        // Custody columns set …
        assertThat(after.accessTokenEnc()).isEqualTo("encAccess");
        // … and the MFA columns are untouched by the custody partial UPDATE.
        assertThat(after.mfaSatisfied()).isTrue();
        assertThat(after.amr()).isEqualTo("webauthn");
        assertThat(after.mfaSatisfiedAt()).isNotNull();
    }

    @Test
    void mfaStamp_doesNotTouchCustodyColumns() {
        seed("bff_iso2");
        // Custody first …
        repo.stampCustody("bff_iso2", "encAccess", "encRefresh",
                LocalDateTime.of(2030, 6, 1, 0, 0)).block();

        // … then an MFA stamp must leave the custody columns intact.
        repo.stampMfaSatisfied("bff_iso2", "otp").block();

        BffSession after = repo.findById("bff_iso2").block();
        assertThat(after.mfaSatisfied()).isTrue();
        assertThat(after.amr()).isEqualTo("otp");
        assertThat(after.accessTokenEnc()).isEqualTo("encAccess");
        assertThat(after.refreshTokenEnc()).isEqualTo("encRefresh");
        assertThat(after.accessTokenExpiresAt()).isEqualTo(LocalDateTime.of(2030, 6, 1, 0, 0));
    }
}

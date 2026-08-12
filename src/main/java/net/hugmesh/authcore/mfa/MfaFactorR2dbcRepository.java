package net.hugmesh.authcore.mfa;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code mfa_factor} (changeset 151). All reads are
 * SCOPED to the owner — the verifier + list + delete only ever touch the caller's own
 * factors (the cross-user isolation keystone). The TOTP enable / counter-advance partial
 * UPDATEs and the owner-scoped delete are {@code @Query} static-final constants; the lookups
 * are derived finders. No raw {@code DatabaseClient} (the data-access standard).
 *
 * <p>DB-GENERATED UUID PK (release 2.3.0): the {@code id} is NO LONGER minted in Java. The
 * production {@code mfa_factor.id} column carries a {@code DEFAULT (gen_random_uuid())::text}
 * (admin-bff changeset 151), so the enroll INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated UUID back. That INSERT is therefore a
 * plain (NON-{@code @Modifying}) {@code @Query} returning {@code Mono<String>} (the new id),
 * NOT a full-entity {@code save} — a {@code Persistable} {@code save} would have to supply the
 * id. The reads / partial UPDATEs / delete are unchanged.
 */
public interface MfaFactorR2dbcRepository extends ReactiveCrudRepository<MfaFactorRow, String> {

    /** Every factor owned by {@code ownerSubject} (the list surface + verifier scan). */
    Flux<MfaFactorRow> findByOwnerSubject(String ownerSubject);

    /** The owner's factors of a given {@code type} (e.g. the in-progress TOTP enroll row). */
    Flux<MfaFactorRow> findByOwnerSubjectAndType(String ownerSubject, String type);

    /** Enroll a factor with a DB-generated id. The {@code id} is OMITTED so Postgres fills it
     *  from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the
     *  generated UUID back. A plain (non-{@code @Modifying}) {@code @Query} returning the new id.
     *  Preserves the enroll shape EXACTLY: a TOTP begin-enroll inserts a DISABLED row with the
     *  encrypted secret ({@code totp_secret_enc}) and null {@code last_counter}; a WebAuthn
     *  mirror inserts an ENABLED row with null secret. */
    String INSERT_FACTOR_RETURNING_ID =
            "INSERT INTO mfa_factor "
            + "(owner_subject, type, totp_secret_enc, last_counter, enabled, created_at) "
            + "VALUES (:ownerSubject, :type, :totpSecretEnc, :lastCounter, :enabled, :createdAt) "
            + "RETURNING id";

    @Query(INSERT_FACTOR_RETURNING_ID)
    Mono<String> insertReturningId(String ownerSubject, String type, String totpSecretEnc,
                                   Long lastCounter, boolean enabled, java.time.Instant createdAt);

    /** Enable a factor and stamp the first accepted TOTP step — keyed on (id, owner) so a
     *  caller can only flip THEIR OWN factor (cross-user isolation at the SQL predicate). */
    String ENABLE_TOTP =
            "UPDATE mfa_factor SET enabled = true, last_counter = :counter "
            + "WHERE id = :id AND owner_subject = :ownerSubject";

    @Modifying
    @Query(ENABLE_TOTP)
    Mono<Long> enableTotp(String id, String ownerSubject, long counter);

    /** Advance the replay guard to the just-accepted step — keyed on (id, owner). The
     *  {@code last_counter < :counter} predicate makes the advance idempotent + rejects a
     *  replay of the SAME or an EARLIER step at the SQL layer (no row updated -> 0). */
    String ADVANCE_COUNTER =
            "UPDATE mfa_factor SET last_counter = :counter "
            + "WHERE id = :id AND owner_subject = :ownerSubject "
            + "AND (last_counter IS NULL OR last_counter < :counter)";

    @Modifying
    @Query(ADVANCE_COUNTER)
    Mono<Long> advanceCounter(String id, String ownerSubject, long counter);

    /** Owner-scoped hard delete (a user removes THEIR OWN factor; step-up gated upstream).
     *  Keyed on (id, owner) so a caller can NEVER delete another subject's factor. Returns
     *  the rows-deleted count (0 = not the caller's factor / no such id). */
    String DELETE_BY_ID_AND_OWNER =
            "DELETE FROM mfa_factor WHERE id = :id AND owner_subject = :ownerSubject";

    @Modifying
    @Query(DELETE_BY_ID_AND_OWNER)
    Mono<Long> deleteByIdAndOwner(String id, String ownerSubject);
}

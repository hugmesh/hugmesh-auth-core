package systems.snapdragon.authcore.mfa;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code webauthn_credential} (changeset 151).
 * Registration INSERTs (after dup check); assertion verify loads the caller's creds and,
 * on success, advances {@code sign_count} MONOTONICALLY (clone detection at the SQL
 * predicate). Owner-scoped delete is the step-up-gated remove. No raw {@code DatabaseClient}.
 */
public interface WebAuthnCredentialR2dbcRepository
        extends ReactiveCrudRepository<WebAuthnCredentialRow, String> {

    /** The owner's registered credentials (the assertion verify candidate set). */
    Flux<WebAuthnCredentialRow> findByOwnerSubject(String ownerSubject);

    /** Global lookup by credentialId (the dup-registration check + the assertion verify
     *  identifies the presented credential). credentialId is UNIQUE, so at most one. */
    Mono<WebAuthnCredentialRow> findByCredentialId(String credentialId);

    /** Advance the sign count MONOTONICALLY after a verified assertion — keyed on (id, owner)
     *  with a {@code sign_count < :newCount} guard so a stale/cloned counter (<=) updates 0
     *  rows. The caller treats a 0-row update on a count that did NOT advance as a clone and
     *  fails the assertion. A genuine 0 (authenticator that always reports 0) is handled by
     *  the verifier's {@code newCount == 0 && stored == 0} allowance BEFORE this call. */
    String ADVANCE_SIGN_COUNT =
            "UPDATE webauthn_credential SET sign_count = :newCount "
            + "WHERE id = :id AND owner_subject = :ownerSubject AND sign_count < :newCount";

    @Modifying
    @Query(ADVANCE_SIGN_COUNT)
    Mono<Long> advanceSignCount(String id, String ownerSubject, long newCount);

    /** Owner-scoped hard delete (step-up gated upstream); returns rows-deleted (0 = not the
     *  caller's credential). */
    String DELETE_BY_ID_AND_OWNER =
            "DELETE FROM webauthn_credential WHERE id = :id AND owner_subject = :ownerSubject";

    @Modifying
    @Query(DELETE_BY_ID_AND_OWNER)
    Mono<Long> deleteByIdAndOwner(String id, String ownerSubject);
}

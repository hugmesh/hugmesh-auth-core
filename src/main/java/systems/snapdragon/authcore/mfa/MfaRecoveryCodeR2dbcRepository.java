package systems.snapdragon.authcore.mfa;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code mfa_recovery_code} (changeset 151). The
 * verifier scans the caller's UNUSED codes and constant-time compares; consume is a
 * one-time CAS (used false->true keyed on id + owner); regenerate hard-deletes the prior
 * owner set. No raw {@code DatabaseClient}.
 */
public interface MfaRecoveryCodeR2dbcRepository
        extends ReactiveCrudRepository<MfaRecoveryCodeRow, String> {

    /** The owner's UNUSED recovery codes (the verifier scan; {@code used=false} only). */
    Flux<MfaRecoveryCodeRow> findByOwnerSubjectAndUsedFalse(String ownerSubject);

    /** One-time consume: flip {@code used} false->true keyed on (id, owner). The
     *  {@code used = false} predicate makes the consume CAS-safe (a concurrent double-spend
     *  loses -> 0 rows), and the owner predicate is the cross-user isolation backstop. */
    String CONSUME =
            "UPDATE mfa_recovery_code SET used = true "
            + "WHERE id = :id AND owner_subject = :ownerSubject AND used = false";

    @Modifying
    @Query(CONSUME)
    Mono<Long> consume(String id, String ownerSubject);

    /** Hard-delete the owner's ENTIRE recovery-code set (a regenerate invalidates the old
     *  set). Owner-scoped so it can never touch another subject's codes. */
    String DELETE_BY_OWNER = "DELETE FROM mfa_recovery_code WHERE owner_subject = :ownerSubject";

    @Modifying
    @Query(DELETE_BY_OWNER)
    Mono<Long> deleteByOwner(String ownerSubject);
}

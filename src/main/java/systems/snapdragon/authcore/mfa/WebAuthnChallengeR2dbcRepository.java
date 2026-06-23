package systems.snapdragon.authcore.mfa;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code webauthn_challenge} (changeset 152). Backs the
 * durable, multi-replica-safe {@link WebAuthnChallengeStore}: a {@code .../options} endpoint
 * INSERTs a pending challenge for (ownerSubject, ceremonyType), and the matching
 * {@code .../verify} CONSUMES it one-time. consume is an atomic CAS (the {@code used = false}
 * + unexpired predicate makes a replay / concurrent double-verify lose -> 0 rows), then the
 * caller re-reads the just-flipped row to recover the challenge. Owner + ceremony scoped so a
 * subject can never consume another subject's challenge. No raw {@code DatabaseClient}.
 *
 * <p>DB-GENERATED UUID PK (release 2.3.0): the {@code id} is NO LONGER minted in Java. The
 * production {@code webauthn_challenge.id} column carries a
 * {@code DEFAULT (gen_random_uuid())::text} (admin-bff changeset 152), so the
 * {@code .../options} INSERT OMITS {@code id} and appends {@code RETURNING id} (a plain,
 * NON-{@code @Modifying} {@code @Query} returning {@code Mono<String>}). The supersede-prune,
 * the unexpired-pending read and the atomic single-use consume are unchanged.
 */
public interface WebAuthnChallengeR2dbcRepository
        extends ReactiveCrudRepository<WebAuthnChallengeRow, String> {

    /** The owner's pending (unused) challenges for a ceremony, freshest first. The store reads
     *  the head of this to recover the challenge consumed by {@link #consume}. */
    Flux<WebAuthnChallengeRow> findByOwnerSubjectAndCeremonyTypeAndUsedFalseOrderByCreatedAtDesc(
            String ownerSubject, String ceremonyType);

    /** Insert a fresh PENDING challenge with a DB-generated id (called by {@code put} AFTER the
     *  supersede-prune). The {@code id} is OMITTED so Postgres fills it from the
     *  {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads it back. A
     *  plain (non-{@code @Modifying}) {@code @Query} returning the new id; a fresh challenge
     *  always inserts {@code used=false}. */
    String INSERT_CHALLENGE_RETURNING_ID =
            "INSERT INTO webauthn_challenge "
            + "(owner_subject, challenge, ceremony_type, expires_at, used, created_at) "
            + "VALUES (:ownerSubject, :challenge, :ceremonyType, :expiresAt, :used, :createdAt) "
            + "RETURNING id";

    @Query(INSERT_CHALLENGE_RETURNING_ID)
    Mono<String> insertReturningId(String ownerSubject, String challenge, String ceremonyType,
                                   Instant expiresAt, boolean used, Instant createdAt);

    /** Atomic one-time consume of ONE exact challenge row. Flip {@code used} false->true keyed
     *  on (id, owner, ceremony) for an UNEXPIRED pending row. The {@code used = false} +
     *  {@code expires_at > :now} predicate makes the consume CAS-safe (a replay / concurrent
     *  second verify of the same row loses -> 0 rows); the owner + ceremony predicates are the
     *  cross-user / cross-ceremony isolation backstop. Returns the rows flipped (1 iff THIS
     *  caller won the still-valid challenge). */
    String CONSUME =
            "UPDATE webauthn_challenge SET used = true "
            + "WHERE id = :id AND owner_subject = :ownerSubject AND ceremony_type = :ceremonyType "
            + "AND used = false AND expires_at > :now";

    @Modifying
    @Query(CONSUME)
    Mono<Long> consume(String id, String ownerSubject, String ceremonyType, Instant now);

    /** Supersede-and-prune: hard-delete ALL of the owner's prior challenges for a ceremony
     *  (called on put). A fresh {@code .../options} call SUPERSEDES any prior pending challenge
     *  for the same (owner, ceremony) — mirroring the old in-memory map's single-slot overwrite —
     *  AND clears used / expired rows so stale rows never accumulate. Owner + ceremony scoped so
     *  it can never touch another subject's rows. */
    String PRUNE =
            "DELETE FROM webauthn_challenge "
            + "WHERE owner_subject = :ownerSubject AND ceremony_type = :ceremonyType";

    @Modifying
    @Query(PRUNE)
    Mono<Long> pruneOwnerCeremony(String ownerSubject, String ceremonyType);
}

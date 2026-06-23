package systems.snapdragon.authcore.mfa;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Short-TTL DURABLE store for the PENDING WebAuthn challenge, bound to the caller's exact
 * authenticated subject + ceremony purpose. The server generates the challenge in the
 * {@code .../options} endpoint, stashes it here, and the {@code .../verify} endpoint consumes
 * it (one-time) — so a verify can only succeed against a challenge THIS subject was just
 * issued (no client-supplied challenge, no cross-subject replay).
 *
 * <p>Backed by the {@code webauthn_challenge} Postgres table (changeset 152) via Spring Data
 * R2DBC, replacing the prior in-process {@code ConcurrentHashMap}. This makes the store
 * DURABLE + MULTI-REPLICA-SAFE: a challenge issued by one admin-bff replica's
 * {@code .../options} is consumable by ANOTHER replica's {@code .../verify} sharing the same
 * DB (the in-memory map failed closed cross-node — a documented multi-replica GO-LIVE blocker).
 *
 * <p>Behavior-preserving except now durable: same ~5m TTL, same single-use (an atomic CAS
 * consume so a replay or a second concurrent verify finds nothing), same owner-subject + purpose
 * scoping. The store only matters when MFA is enabled (the whole surface ships dark behind
 * {@code app.casdoor.mfa.enabled}).
 */
@Component
public class WebAuthnChallengeStore {

    /** Registration ceremony purpose key (stored as {@code ceremony_type}). Byte-identical to
     *  {@link CeremonyType#REGISTER}'s wire token; delegates to the enum (single source of truth). */
    public static final String PURPOSE_REGISTER = CeremonyType.REGISTER.value();
    /** Assertion ceremony purpose key (stored as {@code ceremony_type}). Byte-identical to
     *  {@link CeremonyType#ASSERT}'s wire token; delegates to the enum (single source of truth). */
    public static final String PURPOSE_ASSERT = CeremonyType.ASSERT.value();

    private static final Duration TTL = Duration.ofMinutes(5);

    private final WebAuthnChallengeR2dbcRepository challenges;

    public WebAuthnChallengeStore(WebAuthnChallengeR2dbcRepository challenges) {
        this.challenges = challenges;
    }

    /** Stash a freshly-issued challenge for (ownerSubject, purpose). Prunes any prior pending /
     *  expired challenge for the same (owner, ceremony) first so a new options call supersedes
     *  the old AND stale rows never accumulate (lazy prune). Returns when the row is durable.
     *  A blank subject / null challenge is a no-op (the verify then fails closed). */
    public Mono<Void> put(String ownerSubject, String purpose, String challengeB64Url) {
        if (ownerSubject == null || ownerSubject.isBlank() || challengeB64Url == null) {
            return Mono.empty();
        }
        Instant now = Instant.now();
        WebAuthnChallengeRow row = new WebAuthnChallengeRow(
                UUID.randomUUID().toString(), ownerSubject, challengeB64Url, purpose,
                now.plus(TTL), false, now, true);
        // Supersede any prior challenge for this (owner, ceremony) — a re-issue replaces it,
        // mirroring the old single-slot map, and stale used/expired rows never accumulate —
        // then insert the fresh pending challenge.
        return challenges.pruneOwnerCeremony(ownerSubject, purpose)
                .then(challenges.save(row))
                .then();
    }

    /** Consume (one-time) the pending challenge for (ownerSubject, purpose). Emits the
     *  challenge ONLY when an unexpired pending one exists and THIS call wins the atomic CAS;
     *  emits empty when none is pending, it is expired, it was already consumed (replay /
     *  concurrent second verify), or the subject is blank — the verify then fails closed. */
    public Mono<String> consume(String ownerSubject, String purpose) {
        if (ownerSubject == null || ownerSubject.isBlank()) {
            return Mono.empty();
        }
        Instant now = Instant.now();
        // Read the freshest unexpired pending row, atomically CAS-consume it by id, and return
        // its challenge only when the CAS flipped exactly that row (single-use; a replay /
        // concurrent verify loses the CAS -> 0 rows -> empty).
        return challenges
                .findByOwnerSubjectAndCeremonyTypeAndUsedFalseOrderByCreatedAtDesc(
                        ownerSubject, purpose)
                .filter(row -> row.expiresAt().isAfter(now))
                .concatMap(row -> challenges.consume(row.id(), ownerSubject, purpose, now)
                        .filter(rows -> rows != null && rows > 0L)
                        .map(rows -> row.challenge()))
                .next();
    }
}

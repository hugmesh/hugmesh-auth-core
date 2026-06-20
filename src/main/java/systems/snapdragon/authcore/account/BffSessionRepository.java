package systems.snapdragon.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code bff_session} (changeset 006 + 150 MFA
 * columns). PK is the opaque {@code token}. The {@link AccountStore} facade composes
 * {@code findById}/{@code save}/{@code deleteById} into session create / resolve / MFA
 * stamp+clear / logout. The MFA-stamp and MFA-clear are partial column updates expressed
 * as {@code @Modifying @Query} (a full-entity {@code save} would clobber the other
 * columns / require a prior read).
 */
public interface BffSessionRepository extends ReactiveCrudRepository<BffSession, String> {

    /** Partial UPDATE: stamp a FRESH MFA satisfaction onto a session by token. */
    String STAMP_MFA =
            "UPDATE bff_session SET mfa_satisfied = true, mfa_satisfied_at = now(), "
            + "amr = :amr WHERE token = :token";

    /** Partial UPDATE: clear the MFA satisfaction on a session by token. */
    String CLEAR_MFA =
            "UPDATE bff_session SET mfa_satisfied = false, mfa_satisfied_at = NULL "
            + "WHERE token = :token";

    /** Stamp a FRESH MFA satisfaction onto a session by token. Returns rows updated
     *  (0 = unknown token). Behaviour-identical to the prior partial UPDATE. */
    @Modifying
    @Query(STAMP_MFA)
    Mono<Long> stampMfaSatisfied(String token, String amr);

    /** Clear the MFA satisfaction on a session by token (single-use consumption).
     *  Returns rows updated (0 = unknown token). */
    @Modifying
    @Query(CLEAR_MFA)
    Mono<Long> clearMfaSatisfied(String token);
}

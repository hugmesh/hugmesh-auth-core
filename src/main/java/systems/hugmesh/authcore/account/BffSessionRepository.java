package systems.hugmesh.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

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

    /** Partial UPDATE: stamp the encrypted OIDC token custody onto a session by token
     *  (band-180 columns). A partial UPDATE so the MFA / lifecycle columns are untouched. */
    String STAMP_CUSTODY =
            "UPDATE bff_session SET access_token_enc = :accessEnc, refresh_token_enc = :refreshEnc, "
            + "access_token_expires_at = :accessExpiresAt, custody_updated_at = now() WHERE token = :token";

    /** Partial UPDATE: clear the custody columns on a session by token (logout / refresh). */
    String CLEAR_CUSTODY =
            "UPDATE bff_session SET access_token_enc = NULL, refresh_token_enc = NULL, "
            + "access_token_expires_at = NULL, custody_updated_at = now() WHERE token = :token";

    /** Stamp the encrypted OIDC tokens + their access-token expiry onto a session by token.
     *  Returns rows updated (0 = unknown token). Does NOT touch the MFA / lifecycle columns. */
    @Modifying
    @Query(STAMP_CUSTODY)
    Mono<Long> stampCustody(String token, String accessEnc, String refreshEnc, LocalDateTime accessExpiresAt);

    /** Clear the custody columns on a session by token. Returns rows updated (0 = unknown token). */
    @Modifying
    @Query(CLEAR_CUSTODY)
    Mono<Long> clearCustody(String token);

    /**
     * List ALL session rows for one account (the "my active sessions" read). Derived query
     * on the indexed {@code account_id} FK column — Spring Data R2DBC emits
     * {@code WHERE account_id = $1}, ordered newest-first for a stable UI listing. Includes
     * EXPIRED rows; callers wanting only live sessions use
     * {@link #findByAccountIdAndExpiresAtAfter(String, LocalDateTime)} (or filter the
     * {@link AccountStore} passthrough). NEVER takes a request-supplied account id — the
     * account is derived server-side from the validated principal (see {@link AccountStore}).
     */
    Flux<BffSession> findByAccountIdOrderByCreatedAtDesc(String accountId);

    /**
     * List only the NON-EXPIRED session rows for one account — the DB-side equivalent of the
     * lazy-reap that {@link AccountStore#sessionOfToken(String)} does per-token. Derived query:
     * {@code WHERE account_id = $1 AND expires_at > $2}, ordered newest-first. Pass
     * {@code LocalDateTime.now()} as the cutoff so an expired-but-not-yet-reaped row is hidden
     * from the listing.
     */
    Flux<BffSession> findByAccountIdAndExpiresAtAfterOrderByCreatedAtDesc(String accountId, LocalDateTime cutoff);
}

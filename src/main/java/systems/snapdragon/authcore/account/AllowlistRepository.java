package systems.snapdragon.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code allowlist} (changeset 003). The table
 * has a COMPOSITE PK ({@code provider, handle}); reads are derived finders, the delete
 * is a derived {@code deleteBy...}, and the portable insert-if-absent is an
 * {@code @Modifying @Query} (the {@code WHERE NOT EXISTS} guard is not derivable). The
 * {@link AccountStore} facade composes these.
 */
public interface AllowlistRepository extends ReactiveCrudRepository<Allowlist, String> {

    /** All handles for a provider, handle-ordered ({@code WHERE provider=? ORDER BY handle}). */
    Flux<Allowlist> findByProviderOrderByHandle(String provider);

    /** Whether a (provider, handle) invite exists. */
    Mono<Boolean> existsByProviderAndHandle(String provider, String handle);

    /** Delete a (provider, handle) invite row (idempotent). */
    Mono<Long> deleteByProviderAndHandle(String provider, String handle);

    /** Portable insert-if-absent on the composite PK — a re-invite is a no-op. */
    String INSERT_IF_ABSENT =
            "INSERT INTO allowlist (provider, handle) "
            + "SELECT :provider, :handle WHERE NOT EXISTS "
            + "(SELECT 1 FROM allowlist WHERE provider = :provider AND handle = :handle)";

    @Modifying
    @Query(INSERT_IF_ABSENT)
    Mono<Long> insertIfAbsent(String provider, String handle);
}

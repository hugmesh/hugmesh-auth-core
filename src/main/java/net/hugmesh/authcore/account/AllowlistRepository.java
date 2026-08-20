package net.hugmesh.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code allowlist} (changesets 003 + 220). The
 * table has a COMPOSITE PK ({@code provider, handle, domain}); reads are derived finders,
 * deletes are derived {@code deleteBy...}, and the portable insert-if-absent is an
 * {@code @Modifying @Query} ({@code WHERE NOT EXISTS} guard, not derivable). The
 * {@link AccountStore} facade composes these.
 *
 * <p>Domain-scoped variants (suffix {@code AndDomain}) are the admin CRUD path AND the
 * registration gate ({@code existsByProviderAndHandleAndDomain}). The unscoped
 * {@code existsByProviderAndHandle} is retained only so callers that are not yet threaded
 * with the requesting domain keep compiling — it is cross-brand permissive, and the
 * {@link AccountStore} facade deprecates it.
 */
public interface AllowlistRepository extends ReactiveCrudRepository<Allowlist, String> {

    /** All handles for a provider in a specific domain, handle-ordered. Admin CRUD read path. */
    Flux<Allowlist> findByProviderAndDomainOrderByHandle(String provider, String domain);

    /** All handles for a provider across ALL domains (SUPERADMIN unscoped list). */
    Flux<Allowlist> findByProviderOrderByHandle(String provider);

    /**
     * Whether a (provider, handle) invite exists in ANY domain. Cross-brand permissive —
     * kept for un-migrated callers only; new call sites use the domain-scoped variant.
     */
    Mono<Boolean> existsByProviderAndHandle(String provider, String handle);

    /**
     * Whether a (provider, handle) invite exists IN {@code domain} — the domain-scoped
     * registration gate. An invite stamped with brand X's domain no longer satisfies
     * brand Y's gate. Single-tenant rows carry the {@code "default"} back-fill domain.
     */
    Mono<Boolean> existsByProviderAndHandleAndDomain(String provider, String handle, String domain);

    /** Delete a (provider, handle, domain) invite row (idempotent, domain-scoped). */
    Mono<Long> deleteByProviderAndHandleAndDomain(String provider, String handle, String domain);

    /** Portable insert-if-absent on (provider, handle, domain) — a re-invite is a no-op. */
    String INSERT_IF_ABSENT =
            "INSERT INTO allowlist (provider, handle, domain) "
            + "SELECT :provider, :handle, :domain WHERE NOT EXISTS "
            + "(SELECT 1 FROM allowlist WHERE provider = :provider AND handle = :handle AND domain = :domain)";

    @Modifying
    @Query(INSERT_IF_ABSENT)
    Mono<Long> insertIfAbsent(String provider, String handle, String domain);
}

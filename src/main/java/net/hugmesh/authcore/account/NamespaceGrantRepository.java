package net.hugmesh.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code namespace_grant} (changesets 005 + 220).
 * The table has a COMPOSITE PK ({@code grantee, namespace, domain}); reads are derived
 * finders, deletes are derived {@code deleteBy...}, and the portable insert-if-absent is
 * an {@code @Modifying @Query} ({@code WHERE NOT EXISTS} guard, not derivable). The
 * {@link AccountStore} facade composes these.
 *
 * <p>Domain-scoped variants are the admin CRUD path. The unscoped
 * {@code findByGranteeOrderByNamespace} is retained for the user-facing "my namespaces"
 * read in admin-bff's {@code AuthController} (not part of this jar; the user can only see
 * their own rows — account-id scope protects that path).
 */
public interface NamespaceGrantRepository extends ReactiveCrudRepository<NamespaceGrant, String> {

    /** A grantee's namespaces in a domain, namespace-ordered. Domain-scoped admin path. */
    Flux<NamespaceGrant> findByGranteeAndDomainOrderByNamespace(String grantee, String domain);

    /** A grantee's namespaces across ALL domains (user "my namespaces" read). */
    Flux<NamespaceGrant> findByGranteeOrderByNamespace(String grantee);

    /** Every grant in a specific domain. Admin CRUD list path. */
    Flux<NamespaceGrant> findByDomainOrderByGranteeAscNamespaceAsc(String domain);

    /** Every grant across ALL domains (SUPERADMIN unscoped list). */
    Flux<NamespaceGrant> findAllByOrderByGranteeAscNamespaceAsc();

    /** Delete a (grantee, namespace, domain) grant (idempotent, domain-scoped). */
    Mono<Long> deleteByGranteeAndNamespaceAndDomain(String grantee, String namespace, String domain);

    /** Portable insert-if-absent on (grantee, namespace, domain) — a re-grant is a no-op. */
    String INSERT_IF_ABSENT =
            "INSERT INTO namespace_grant (grantee, namespace, domain) "
            + "SELECT :grantee, :namespace, :domain WHERE NOT EXISTS "
            + "(SELECT 1 FROM namespace_grant WHERE grantee = :grantee AND namespace = :namespace AND domain = :domain)";

    @Modifying
    @Query(INSERT_IF_ABSENT)
    Mono<Long> insertIfAbsent(String grantee, String namespace, String domain);
}

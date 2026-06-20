package systems.snapdragon.authcore.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code namespace_grant} (changeset 005). The
 * table has a COMPOSITE PK ({@code grantee, namespace}); reads are derived finders, the
 * delete is a derived {@code deleteBy...}, and the portable insert-if-absent is an
 * {@code @Modifying @Query} ({@code WHERE NOT EXISTS} guard, not derivable). The {@link
 * AccountStore} facade composes these.
 */
public interface NamespaceGrantRepository extends ReactiveCrudRepository<NamespaceGrant, String> {

    /** A grantee's namespaces, namespace-ordered ({@code WHERE grantee=? ORDER BY namespace}). */
    Flux<NamespaceGrant> findByGranteeOrderByNamespace(String grantee);

    /** Every grant, grantee-then-namespace ordered ({@code ORDER BY grantee, namespace}). */
    Flux<NamespaceGrant> findAllByOrderByGranteeAscNamespaceAsc();

    /** Delete a (grantee, namespace) grant (idempotent). */
    Mono<Long> deleteByGranteeAndNamespace(String grantee, String namespace);

    /** Portable insert-if-absent on the composite PK — a re-grant is a no-op. */
    String INSERT_IF_ABSENT =
            "INSERT INTO namespace_grant (grantee, namespace) "
            + "SELECT :grantee, :namespace WHERE NOT EXISTS "
            + "(SELECT 1 FROM namespace_grant WHERE grantee = :grantee AND namespace = :namespace)";

    @Modifying
    @Query(INSERT_IF_ABSENT)
    Mono<Long> insertIfAbsent(String grantee, String namespace);
}

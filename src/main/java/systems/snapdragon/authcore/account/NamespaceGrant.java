package systems.snapdragon.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code namespace_grant} (Liquibase changeset 005) — a per-user namespace
 * grant. The PK is COMPOSITE ({@code grantee, namespace}); like {@link Allowlist}, reads
 * use derived finders, deletes a derived {@code deleteBy...}, and the portable
 * insert-if-absent stays an {@code @Modifying @Query}. The {@code @Id} on {@code grantee}
 * satisfies the repository's ID type only.
 */
@Table("namespace_grant")
public record NamespaceGrant(
        @Id @Column("grantee") String grantee,
        @Column("namespace") String namespace,
        @Column("created_at") LocalDateTime createdAt) {
}

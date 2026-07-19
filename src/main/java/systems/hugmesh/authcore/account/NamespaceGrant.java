package systems.hugmesh.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code namespace_grant} (Liquibase changesets 005 + 220) — a per-user
 * namespace grant. The PK is COMPOSITE ({@code grantee, namespace, domain}); like
 * {@link Allowlist}, reads use derived finders, deletes use derived {@code deleteBy...},
 * and the portable insert-if-absent stays an {@code @Modifying @Query}. The {@code @Id}
 * on {@code grantee} satisfies the repository's ID type only.
 *
 * <p><b>Domain:</b> the per-brand tenant discriminator (changeset 220). Existing rows
 * back-fill to {@code "default"}. A brand-scoped ADMIN sees and manages only their
 * brand's grants; SUPERADMIN is unscoped.
 */
@Table("namespace_grant")
public record NamespaceGrant(
        @Id @Column("grantee") String grantee,
        @Column("namespace") String namespace,
        @Column("domain") String domain,
        @Column("created_at") LocalDateTime createdAt) {
}

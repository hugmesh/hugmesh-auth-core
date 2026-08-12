package net.hugmesh.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code allowlist} (Liquibase changesets 003 + 220) — the admin-managed
 * provider+handle+domain invite list. The PK is COMPOSITE ({@code provider, handle,
 * domain}); Spring Data R2DBC has no composite-id support, so reads use derived finders,
 * deletes use derived {@code deleteBy...}, and the portable insert-if-absent stays an
 * {@code @Modifying @Query}. The {@code @Id} on {@code handle} satisfies the
 * repository's ID type only — {@code save}/{@code findById} are never used directly.
 *
 * <p><b>Domain:</b> the per-brand tenant discriminator (changeset 220). Existing rows
 * back-fill to {@code "default"} (the single-tenant domain). A brand-scoped ADMIN's
 * invite rows are stamped with their brand's domain and filtered to that brand on reads.
 * SUPERADMIN is unscoped and sees all brands' rows.
 */
@Table("allowlist")
public record Allowlist(
        @Column("provider") String provider,
        @Id @Column("handle") String handle,
        @Column("domain") String domain,
        @Column("created_at") LocalDateTime createdAt) {
}

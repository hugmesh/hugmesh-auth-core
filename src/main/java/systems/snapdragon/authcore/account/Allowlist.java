package systems.snapdragon.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code allowlist} (Liquibase changeset 003) — the admin-managed
 * provider+handle invite list. The PK is COMPOSITE ({@code provider, handle}); Spring
 * Data R2DBC has no composite-id support, so reads use derived finders, deletes use a
 * derived {@code deleteBy...}, and the portable insert-if-absent stays an
 * {@code @Modifying @Query} (the {@code WHERE NOT EXISTS} guard is not derivable). The
 * {@code @Id} on {@code handle} satisfies the repository's ID type only — {@code
 * save}/{@code findById} are never used on this entity.
 */
@Table("allowlist")
public record Allowlist(
        @Column("provider") String provider,
        @Id @Column("handle") String handle,
        @Column("created_at") LocalDateTime createdAt) {
}

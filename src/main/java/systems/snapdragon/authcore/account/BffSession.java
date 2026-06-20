package systems.snapdragon.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code bff_session} (Liquibase changeset 006 + the 150 MFA columns) — an
 * opaque application-level BFF session. {@code token} is the assigned PK ({@code
 * varchar(64)}), so the entity implements {@link Persistable} to force the INSERT for a
 * freshly-minted session.
 *
 * <p>Columns: {@code account_id}, {@code created_at}, {@code expires_at} (all changeset
 * 006), plus {@code mfa_satisfied} / {@code mfa_satisfied_at} / {@code amr} (changeset
 * 150). Timestamps are {@code timestamp} (no zone) → {@code LocalDateTime}, matching the
 * facade's prior binds.
 */
@Table("bff_session")
public record BffSession(
        @Id @Column("token") String token,
        @Column("account_id") String accountId,
        @Column("created_at") LocalDateTime createdAt,
        @Column("expires_at") LocalDateTime expiresAt,
        @Column("mfa_satisfied") boolean mfaSatisfied,
        @Column("mfa_satisfied_at") LocalDateTime mfaSatisfiedAt,
        @Column("amr") String amr,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public BffSession(String token, String accountId, LocalDateTime createdAt, LocalDateTime expiresAt,
                      boolean mfaSatisfied, LocalDateTime mfaSatisfiedAt, String amr) {
        this(token, accountId, createdAt, expiresAt, mfaSatisfied, mfaSatisfiedAt, amr, false);
    }

    @Override
    public String getId() {
        return token;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}

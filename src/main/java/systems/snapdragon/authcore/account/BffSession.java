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
 * 150), plus {@code access_token_enc} / {@code refresh_token_enc} /
 * {@code access_token_expires_at} / {@code custody_updated_at} (the admin-bff band-180 OIDC
 * token-custody migration). The custody columns are NULLABLE and never written by
 * {@link AccountStore#newSession} — they are stamped only by the dark custody endpoints, so a
 * 2.0.0 consumer running before band-180 reads them as null. Timestamps are {@code timestamp}
 * (no zone) → {@code LocalDateTime}, matching the facade's prior binds.
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
        @Column("access_token_enc") String accessTokenEnc,
        @Column("refresh_token_enc") String refreshTokenEnc,
        @Column("access_token_expires_at") LocalDateTime accessTokenExpiresAt,
        @Column("custody_updated_at") LocalDateTime custodyUpdatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    /**
     * Canonical (non-{@code isNew}-defaulting) creator — the ONE {@code @PersistenceCreator}.
     * Spring Data materialises a loaded row through this with {@code isNew=false}.
     */
    @org.springframework.data.annotation.PersistenceCreator
    public BffSession(String token, String accountId, LocalDateTime createdAt, LocalDateTime expiresAt,
                      boolean mfaSatisfied, LocalDateTime mfaSatisfiedAt, String amr,
                      String accessTokenEnc, String refreshTokenEnc,
                      LocalDateTime accessTokenExpiresAt, LocalDateTime custodyUpdatedAt) {
        this(token, accountId, createdAt, expiresAt, mfaSatisfied, mfaSatisfiedAt, amr,
                accessTokenEnc, refreshTokenEnc, accessTokenExpiresAt, custodyUpdatedAt, false);
    }

    /**
     * Convenience creator for the mint path: custody is stamped later (never at mint), so the
     * four custody columns default to null. Keeps {@link AccountStore#newSession}'s 8-arg call
     * site unchanged. NOT a {@code @PersistenceCreator} — there is exactly one of those.
     */
    public BffSession(String token, String accountId, LocalDateTime createdAt, LocalDateTime expiresAt,
                      boolean mfaSatisfied, LocalDateTime mfaSatisfiedAt, String amr, boolean isNew) {
        this(token, accountId, createdAt, expiresAt, mfaSatisfied, mfaSatisfiedAt, amr,
                null, null, null, null, isNew);
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

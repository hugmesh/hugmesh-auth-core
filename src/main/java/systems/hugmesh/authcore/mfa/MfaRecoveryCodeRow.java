package systems.hugmesh.authcore.mfa;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code mfa_recovery_code} (Liquibase changeset 151) — a single recovery code,
 * stored as ONLY a salted HMAC-SHA256 hash (base64), NEVER the plaintext code. {@code used}
 * flips one-time on consume; a regenerate hard-deletes the prior set. {@code ownerSubject}
 * is the authenticated subject (never a body field). App-generated UUID PK; implements
 * {@link Persistable} so a fresh row INSERTs.
 */
@Table("mfa_recovery_code")
public record MfaRecoveryCodeRow(
        @Id @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("code_hash") String codeHash,
        @Column("used") boolean used,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public MfaRecoveryCodeRow(String id, String ownerSubject, String codeHash, boolean used,
                              Instant createdAt) {
        this(id, ownerSubject, codeHash, used, createdAt, false);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}

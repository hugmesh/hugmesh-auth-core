package net.hugmesh.authcore.mfa;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code webauthn_challenge} (Liquibase changeset 152) — a single PENDING WebAuthn
 * challenge bound to an authenticated {@code ownerSubject} + {@code ceremonyType}
 * ({@code REGISTER} | {@code ASSERT}). {@code challenge} is the base64url server nonce;
 * {@code expiresAt} is the ~5m absolute deadline (consume rejects an expired row);
 * {@code used} flips one-time on consume (single-use). {@code ownerSubject} is the
 * authenticated subject (never a body field). App-generated UUID PK; implements
 * {@link Persistable} so a fresh row INSERTs.
 */
@Table("webauthn_challenge")
public record WebAuthnChallengeRow(
        @Id @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("challenge") String challenge,
        @Column("ceremony_type") String ceremonyType,
        @Column("expires_at") Instant expiresAt,
        @Column("used") boolean used,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public WebAuthnChallengeRow(String id, String ownerSubject, String challenge,
                                String ceremonyType, Instant expiresAt, boolean used,
                                Instant createdAt) {
        this(id, ownerSubject, challenge, ceremonyType, expiresAt, used, createdAt, false);
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

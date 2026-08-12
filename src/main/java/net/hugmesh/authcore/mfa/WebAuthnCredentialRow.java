package net.hugmesh.authcore.mfa;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code webauthn_credential} (Liquibase changeset 151) — a registered WebAuthn
 * credential owned by a subject.
 *
 * <p>{@code credentialId} is the base64url-encoded WebAuthn credential id (UNIQUE — no dup
 * registration). {@code publicKeyCose} is the base64-encoded COSE public key the assertion
 * signature verifies against. {@code signCount} is the running authenticator counter that an
 * assertion MUST advance (clone detection). {@code ownerSubject} is the authenticated
 * subject, never a body field. App-generated UUID PK; implements {@link Persistable}.
 */
@Table("webauthn_credential")
public record WebAuthnCredentialRow(
        @Id @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("credential_id") String credentialId,
        @Column("public_key_cose") String publicKeyCose,
        @Column("sign_count") long signCount,
        @Column("transports") String transports,
        @Column("enabled") boolean enabled,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public WebAuthnCredentialRow(String id, String ownerSubject, String credentialId,
                                 String publicKeyCose, long signCount, String transports,
                                 boolean enabled, Instant createdAt) {
        this(id, ownerSubject, credentialId, publicKeyCose, signCount, transports, enabled,
                createdAt, false);
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

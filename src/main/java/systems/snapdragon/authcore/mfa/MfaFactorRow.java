package systems.snapdragon.authcore.mfa;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code mfa_factor} (Liquibase changeset 151) — an enrolled TOTP or WebAuthn
 * second factor owned by an authenticated subject.
 *
 * <p>SECURITY: {@code ownerSubject} is the authenticated {@code bff_session} subject
 * (JWT {@code sub} / auth name), NEVER a request-body field. {@code totpSecretEnc} holds
 * the AES-256-GCM {@code nonce||ciphertext||tag} (base64) of the TOTP shared secret — it
 * is NEVER plaintext, NEVER returned after enroll, NEVER logged; it is NULL for a WEBAUTHN
 * factor. {@code enabled} DEFAULTS false (band 151) so a mid-enroll factor never satisfies
 * a challenge. {@code lastCounter} is the last-accepted TOTP step (the replay guard).
 *
 * <p>App-generated {@code varchar(36)} UUID PK; implements {@link Persistable} so a freshly
 * minted row INSERTs (the data-access standard's record-entity idiom, cf. {@code AppProfileRow}).
 */
@Table("mfa_factor")
public record MfaFactorRow(
        @Id @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("type") String type,
        @Column("totp_secret_enc") String totpSecretEnc,
        @Column("last_counter") Long lastCounter,
        @Column("enabled") boolean enabled,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    /** TOTP factor type discriminator. Byte-identical to {@link FactorType#TOTP}'s wire token;
     *  delegates to the enum so the closed set has a single source of truth. */
    public static final String TYPE_TOTP = FactorType.TOTP.value();
    /** WebAuthn factor type discriminator. Byte-identical to {@link FactorType#WEBAUTHN}'s wire
     *  token; delegates to the enum so the closed set has a single source of truth. */
    public static final String TYPE_WEBAUTHN = FactorType.WEBAUTHN.value();

    @PersistenceCreator
    public MfaFactorRow(String id, String ownerSubject, String type, String totpSecretEnc,
                        Long lastCounter, boolean enabled, Instant createdAt) {
        this(id, ownerSubject, type, totpSecretEnc, lastCounter, enabled, createdAt, false);
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

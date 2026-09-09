package net.hugmesh.authcore.account;

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
 *
 * <p><b>Casdoor UUID {@code sub} — asked and ANSWERED; deliberately NOT carried here.</b>
 * This class used to carry an open question ("a consumer that needs the real Casdoor subject
 * would need a new {@code casdoor_sub} column + a version bump here; not yet needed by any
 * landed feature"). A consumer since appeared and the need is fully served WITHOUT a change
 * to this module, so the question is closed rather than pending:
 *
 * <ul>
 *   <li><b>Who needed it:</b> the gateway's {@code GatewayRouteAccessFilter}. It matches
 *       {@code casdoor_user} route pins against a per-user identity set that, for a real
 *       Casdoor-JWT carrier, includes the raw UUID {@code sub}. For a native-login
 *       {@code bff_} session carrier that set was built only from the durable account id
 *       ({@code casdoor:<handle>}), so a UUID-form pin matched the JWT carrier but never the
 *       SAME human on a session cookie — a UUID ALLOW pin wrongly denied them and, worse, a
 *       UUID DENY pin (a targeted ban) failed OPEN. (The "A5 part-B" cross-carrier gap.)</li>
 *   <li><b>Where it landed:</b> admin-bff, on the {@code account} table — Liquibase changeset
 *       {@code 292-account-casdoor-sub} adds a nullable, non-unique {@code account.casdoor_sub},
 *       stamped from the one place the raw id_token is decoded
 *       ({@code InternalAccountController#ensureAccount}, {@code provider="casdoor"}) through
 *       {@code AccountCasdoorSubService}, and surfaced by
 *       {@code /bff/internal/session/introspect} as a nullable {@code casdoorSub} field that
 *       the gateway folds into the pin-match set ({@code BffSessionAuthFilter.SessionDetails}).</li>
 *   <li><b>Why NOT on this record:</b> the subject belongs to the <i>account</i>, not to a
 *       session — one human's sessions all resolve to the same account id, and introspect
 *       already reads the value by {@code accountId}, so a per-session copy would be pure
 *       denormalisation with a staleness window and no new capability. It is not on
 *       {@link Account}/{@code AccountRow} either, by the same deliberate call recorded on
 *       admin-bff's {@code AccountCasdoorSubRow}: auth-core is a separately-versioned shared
 *       dependency, so a field here would force a version-bump chain through every consumer
 *       for a column exactly one of them writes and reads. admin-bff instead maps a narrow
 *       {@code (id, casdoor_sub)} projection over the same physical table.</li>
 * </ul>
 *
 * <p>Consequences for THIS module, both already true: {@link AccountStore}'s INSERT path must
 * keep leaving {@code account.casdoor_sub} alone (which is why changeset 292 is nullable with
 * no default — a NOT NULL there would fail every account creation from here), and no query in
 * this module may {@code SELECT *} over {@code account} or {@code bff_session}, so an
 * unmapped consumer-owned column stays invisible to it. See hugmesh-auth-core#5, whose first
 * bullet this resolves.
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

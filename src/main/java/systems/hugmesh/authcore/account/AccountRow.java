package systems.hugmesh.authcore.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of the {@code account} table (Liquibase changeset 004) — the durable storage
 * shape for an {@link Account}. {@code id} (provider:handle) is the assigned PK, so the
 * entity implements {@link Persistable} to control INSERT vs UPDATE.
 *
 * <p>{@code roles} is the raw CSV column ({@code varchar(255)}); {@link Account} carries
 * the parsed {@code List<String>}. {@link AccountStore} maps between the two so the
 * domain record stays coherent for all consumers (it is constructed all over the code).
 */
@Table("account")
public record AccountRow(
        @Id @Column("id") String id,
        @Column("provider") String provider,
        @Column("handle") String handle,
        @Column("registration_complete") boolean registrationComplete,
        @Column("roles") String roles,
        @Column("updated_at") LocalDateTime updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public AccountRow(String id, String provider, String handle, boolean registrationComplete,
                      String roles, LocalDateTime updatedAt) {
        this(id, provider, handle, registrationComplete, roles, updatedAt, false);
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

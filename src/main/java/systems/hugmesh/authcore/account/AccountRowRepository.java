package systems.hugmesh.authcore.account;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;

/**
 * Reactive (R2DBC) Spring Data store for the {@code account} table (changeset 004).
 * The {@link AccountStore} facade composes {@code findById}/{@code save} into the
 * get-or-create + completion-flag lifecycle, mapping rows to/from the {@link Account}
 * domain record.
 */
public interface AccountRowRepository extends ReactiveCrudRepository<AccountRow, String> {
}

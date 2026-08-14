package net.hugmesh.authcore.account;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit-level (repositories mocked, no database) cover for the native-login
 * {@link AccountStore#ensureAccount(String, String, java.util.List)} overload — the fix that
 * lets a real Casdoor role grant (mod/superadmin/matrix/etc, not just the legacy user/admin
 * pair) reach an account's stored roles on every login, not just at creation.
 */
class AccountStoreEnsureAccountRolesTest {

    private final AllowlistRepository allowlist = mock(AllowlistRepository.class);
    private final AccountRowRepository accounts = mock(AccountRowRepository.class);
    private final BffSessionRepository sessions = mock(BffSessionRepository.class);
    private final NamespaceGrantRepository grants = mock(NamespaceGrantRepository.class);

    private AccountStore store() {
        return new AccountStore(allowlist, accounts, sessions, grants, "admin@hugmesh.net");
    }

    @Test
    void withRoles_newAccount_createsWithGivenRoles() {
        when(accounts.findById("casdoor:e2e-admin")).thenReturn(Mono.empty());
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account a = store().ensureAccount("casdoor", "e2e-admin", List.of("admin", "user")).block();

        assertThat(a.roles()).containsExactly("admin", "user");
        assertThat(a.registrationComplete()).isFalse();
    }

    @Test
    void withRoles_existingAccount_syncsRolesOnEveryCall() {
        // The core fix: an account previously stored with the legacy "user"-only default
        // must be REWRITTEN with the real roles on the next call, not left frozen.
        AccountRow existing = new AccountRow(
                "casdoor:e2e-mod", "casdoor", "e2e-mod", false, "user", LocalDateTime.now().minusDays(1));
        when(accounts.findById("casdoor:e2e-mod")).thenReturn(Mono.just(existing));
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account synced = store().ensureAccount("casdoor", "e2e-mod", List.of("mod", "user")).block();

        // The whole point of the fix: the RETURNED (and thus persisted) roles are the
        // fresh sync values, not the stale stored "user" — proving the existing row was
        // actually rewritten, not just read back unchanged.
        assertThat(synced.roles()).containsExactlyInAnyOrder("mod", "user");
    }

    @Test
    void withRoles_syncPreservesRegistrationComplete() {
        AccountRow existing = new AccountRow(
                "casdoor:e2e-user", "casdoor", "e2e-user", true, "user", LocalDateTime.now().minusDays(1));
        when(accounts.findById("casdoor:e2e-user")).thenReturn(Mono.just(existing));
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account resynced = store().ensureAccount("casdoor", "e2e-user", List.of("user", "matrix")).block();

        assertThat(resynced.registrationComplete()).isTrue();
        assertThat(resynced.roles()).containsExactlyInAnyOrder("user", "matrix");
    }

    @Test
    void nullOrEmptyRoles_delegatesToLegacyTwoArgOverload_existingAccountIsReadOnly() {
        // The bug an independent review caught pre-merge: the null/empty branch must NOT
        // independently recompute-and-rewrite an existing row (that would let a repeat
        // google/discord provider call silently re-derive the admin flag from the LIVE
        // admin-emails config and overwrite whatever was actually stored). It must be a
        // pure read for an existing account, exactly like the plain 2-arg overload.
        // Stored roles deliberately DIFFER from what a fresh admin-emails-config
        // recompute would produce for this handle, so a wrongful rewrite is provable:
        // if the read-only contract were violated, the result would come back as
        // ["user","admin"] (the recomputed default) rather than this stored value.
        AccountRow existing = new AccountRow(
                "google:admin@hugmesh.net", "google", "admin@hugmesh.net",
                true, "user,admin,superadmin", LocalDateTime.now().minusDays(1));
        when(accounts.findById("google:admin@hugmesh.net")).thenReturn(Mono.just(existing));
        // Stubbed only so the (unsubscribed, never-taken) switchIfEmpty branch's eager
        // Mono construction doesn't NPE — it is never actually exercised for an existing
        // row, which is exactly the behavior this test proves via the returned roles.
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account viaNull = store().ensureAccount("google", "admin@hugmesh.net", null).block();
        Account viaEmpty = store().ensureAccount("google", "admin@hugmesh.net", List.of()).block();

        assertThat(viaNull.roles()).containsExactly("user", "admin", "superadmin");
        assertThat(viaEmpty.roles()).containsExactly("user", "admin", "superadmin");
    }

    @Test
    void nullRoles_newAccount_stillAppliesGoogleAdminEmailsDefault() {
        when(accounts.findById("google:admin@hugmesh.net")).thenReturn(Mono.empty());
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account a = store().ensureAccount("google", "admin@hugmesh.net", null).block();

        assertThat(a.roles()).containsExactly("user", "admin");
        assertThat(a.isAdmin()).isTrue();
    }
}

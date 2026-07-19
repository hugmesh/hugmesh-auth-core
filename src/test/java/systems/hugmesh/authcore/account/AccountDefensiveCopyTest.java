package systems.hugmesh.authcore.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@link Account#roles()} is authorization-bearing — {@link Account#isAdmin()} reads it and
 * BffCookieAuthenticationWebFilter turns it into granted authorities. The record therefore has
 * to own its own copy of the list, not alias the caller's.
 *
 * <p>auth-core is a LIBRARY: the callers are user-bff / admin-bff, out of this repo's control,
 * so "no in-repo caller currently passes a mutable list" is not a defence.
 */
class AccountDefensiveCopyTest {

    @Test
    @DisplayName("mutating the caller's list after construction cannot grant admin")
    void callerCannotEscalateByMutatingTheListItPassedIn() {
        List<String> callerOwned = new ArrayList<>(List.of("user"));
        Account account = new Account("google:u@x.com", "google", "u@x.com", true, callerOwned);

        assertThat(account.isAdmin()).isFalse();

        // The caller still holds a reference to the list it handed in. Without a defensive copy
        // in the canonical constructor this line silently promotes the account to admin.
        callerOwned.add("admin");

        assertThat(account.isAdmin()).isFalse();
        assertThat(account.roles()).containsExactly("user");
    }

    @Test
    @DisplayName("roles() hands back an immutable list, so readers cannot mutate the record")
    void rolesAccessorIsNotMutable() {
        Account account = new Account("google:u", "google", "u", true, List.of("user"));

        assertThatThrownBy(() -> account.roles().add("admin"))
                .isInstanceOf(UnsupportedOperationException.class);

        assertThat(account.isAdmin()).isFalse();
    }

    @Test
    @DisplayName("null roles stays null — AccountStore/BffCookieAuthenticationWebFilter branch on it")
    void nullRolesIsPreservedNotNormalised() {
        Account account = new Account("google:norow", "google", "norow", true, null);

        assertThat(account.roles()).isNull();
        assertThat(account.isAdmin()).isFalse();
    }

    @Test
    @DisplayName("withRegistrationComplete carries roles across without re-aliasing")
    void withRegistrationCompletePreservesRoles() {
        List<String> callerOwned = new ArrayList<>(List.of("user", "admin"));
        Account account = new Account("google:a", "google", "a", false, callerOwned);

        Account completed = account.withRegistrationComplete(true);

        callerOwned.clear();

        assertThat(completed.registrationComplete()).isTrue();
        assertThat(completed.roles()).containsExactly("user", "admin");
        assertThat(completed.isAdmin()).isTrue();
    }
}

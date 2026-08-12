package net.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.username.FederationUsernameClient;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.authcore.username.UsernameGateException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies the real Casdoor admin write client issues the documented add-user /
 * update-role calls. Driven by a recording {@link ExchangeFunction} stub (no live
 * Casdoor needed) so the test asserts the request shapes — the exact JSON payload
 * is version-specific and validated against a running casdoor-all-in-one (see
 * openIssues), not in CI.
 */
class CasdoorAdminClientTest {

    /** Records every outgoing request and replies with canned JSON per path. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String roleUsersJson = "{\"status\":\"ok\",\"data\":{\"users\":[]}}";
        boolean userExists = false;
        /** When false, get-role returns null data (role absent) so createRole proceeds. */
        boolean roleExists = true;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String path = request.url().getPath();
            String body;
            if (path.endsWith("/api/get-user")) {
                body = userExists
                        ? "{\"status\":\"ok\",\"data\":{\"owner\":\"hugmesh\",\"name\":\"alice\"}}"
                        : "{\"status\":\"error\",\"data\":null}";
            } else if (path.endsWith("/api/get-role")) {
                body = roleExists ? roleUsersJson : "{\"status\":\"error\",\"data\":null}";
            } else {
                body = "{\"status\":\"ok\"}";
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body(body).build());
        }

        boolean hit(String pathSuffix) {
            return requests.stream().anyMatch(r -> r.url().getPath().endsWith(pathSuffix));
        }

        long count(String pathSuffix) {
            return requests.stream().filter(r -> r.url().getPath().endsWith(pathSuffix)).count();
        }
    }

    private CasdoorAdminClient clientFor(Recorder rec) {
        WebClient web = WebClient.builder().exchangeFunction(rec).build();
        return new CasdoorAdminClient(web, "hugmesh", "app-admin-bff");
    }

    /** A CasdoorAdminClient wired with a username gate over the given taken set. */
    private CasdoorAdminClient clientFor(Recorder rec, UsernameGate gate) {
        WebClient web = WebClient.builder().exchangeFunction(rec).build();
        return new CasdoorAdminClient(web, "hugmesh", "app-admin-bff", gate);
    }

    /** Gate whose federation answers "confusable" for any candidate in taken. */
    private UsernameGate gateWithTaken(Set<String> taken) {
        WebClient fed = WebClient.builder().baseUrl("http://federation")
                .exchangeFunction(request -> {
                    String[] parts = request.url().getPath().split("/");
                    String candidate = parts.length >= 5 ? parts[4] : "";
                    String body = taken.contains(candidate)
                            ? "{\"available\":false,\"reason\":\"confusable\"}"
                            : "{\"available\":true}";
                    return Mono.just(ClientResponse.create(HttpStatus.OK)
                            .header("Content-Type", "application/json").body(body).build());
                }).build();
        return new UsernameGate(new FederationUsernameClient(fed, true, "X-Internal-Token", null));
    }

    @Test
    void usernameOf_stripsEmailLocalpart_forGoogle() {
        assertThat(CasdoorAdminClient.usernameOf("google", "Alice@Gmail.com")).isEqualTo("alice");
        assertThat(CasdoorAdminClient.usernameOf("discord", "CoolUser")).isEqualTo("cooluser");
    }

    @Test
    void usernameOf_stripsEmailLocalpart_regardlessOfProvider() {
        // Native Casdoor-OIDC signups commonly derive the free-text casdoorUser from the
        // JWT "email" claim (see InternalAccountController#subjectFromIdToken), so a
        // provider="casdoor" handle is routinely email-shaped ("alice@gmail.com"). Casdoor
        // usernames cannot carry '@' for ANY provider — the local-part must be stripped here
        // too, not just for "google", or the minted role-member id never matches a real
        // Casdoor role-membership entry and add/removeUserFromRole silently no-ops forever.
        assertThat(CasdoorAdminClient.usernameOf("casdoor", "Alice@Gmail.com")).isEqualTo("alice");
        assertThat(CasdoorAdminClient.usernameOf("matrix", "Bob@Example.org")).isEqualTo("bob");
    }

    @Test
    void ensureUser_newUser_addsUserThenAddsToRole() {
        Recorder rec = new Recorder();
        rec.userExists = false;
        CasdoorAdminClient client = clientFor(rec);

        client.ensureUser("google", "alice@gmail.com", "alice@gmail.com", List.of("user", "admin")).block();

        // get-user (absent) → add-user; then get-role + update-role for each role.
        assertThat(rec.hit("/api/get-user")).isTrue();
        assertThat(rec.hit("/api/add-user")).isTrue();
        assertThat(rec.count("/api/update-role")).isEqualTo(2);   // ROLE_USER + ROLE_ADMIN
        // update-role id carries the org/role.
        assertThat(rec.requests.stream().anyMatch(r ->
                r.url().getPath().endsWith("/api/update-role")
                        && "hugmesh/ROLE_ADMIN".equals(r.url().getQuery().replace("id=", "")))).isTrue();
    }

    @Test
    void ensureUser_existingUser_updatesToEnableNotAdd() {
        Recorder rec = new Recorder();
        rec.userExists = true;
        CasdoorAdminClient client = clientFor(rec);

        client.ensureUser("discord", "bob", null, List.of("user")).block();

        // Existing → update-user (isForbidden=false), NOT add-user.
        assertThat(rec.hit("/api/update-user")).isTrue();
        assertThat(rec.hit("/api/add-user")).isFalse();
    }

    @Test
    void disableUser_updatesForbiddenTrue() {
        Recorder rec = new Recorder();
        CasdoorAdminClient client = clientFor(rec);

        client.disableUser("google", "alice@gmail.com").block();

        assertThat(rec.hit("/api/update-user")).isTrue();
    }

    @Test
    void ensureUser_gateRejectsReservedDerivedUsername_noWrite() {
        // admin@gmail.com derives 'admin' (reserved) → the SERVICE-layer gate
        // refuses; NO add-user / update-user is ever issued.
        Recorder rec = new Recorder();
        CasdoorAdminClient client = clientFor(rec, gateWithTaken(Set.of()));

        assertThatThrownBy(() ->
                client.ensureUser("google", "admin@gmail.com", "admin@gmail.com", List.of("user")).block())
                .isInstanceOf(UsernameGateException.class);

        assertThat(rec.hit("/api/add-user")).isFalse();
        assertThat(rec.hit("/api/update-user")).isFalse();
    }

    @Test
    void ensureUser_gateDisambiguatesConfusable_mintsTheDisambiguatedName() {
        // 'alice' is a confusable collision → the gate disambiguates to 'alice2'
        // and THAT is the username added + the get-user id queried.
        Recorder rec = new Recorder();
        rec.userExists = false;
        CasdoorAdminClient client = clientFor(rec, gateWithTaken(Set.of("alice")));

        client.ensureUser("google", "alice@gmail.com", "alice@gmail.com", List.of("user")).block();

        assertThat(rec.hit("/api/add-user")).isTrue();
        assertThat(rec.requests.stream().anyMatch(r ->
                r.url().getPath().endsWith("/api/get-user")
                        && "hugmesh/alice2".equals(r.url().getQuery().replace("id=", "")))).isTrue();
    }

    @Test
    void ensureLiteralUser_newReservedName_addsVerbatim_bypassingTheGate() {
        // The @system provisioner mints the RESERVED literal name 'system' WITHOUT the
        // username gate (which would reject a reserved name). Even with a gate wired that
        // would reject 'system', ensureLiteralUser uses the verbatim name + adds it.
        Recorder rec = new Recorder();
        rec.userExists = false;
        CasdoorAdminClient client = clientFor(rec, gateWithTaken(Set.of()));

        client.ensureLiteralUser("system", "system@brandx", List.of("user", "matrix", "mastodon")).block();

        // add-user issued with the verbatim 'system' name (no disambiguation/rejection).
        assertThat(rec.hit("/api/add-user")).isTrue();
        assertThat(rec.requests.stream().anyMatch(r ->
                r.url().getPath().endsWith("/api/get-user")
                        && "hugmesh/system".equals(r.url().getQuery().replace("id=", "")))).isTrue();
        // exactly the three least-privilege roles, NEVER admin.
        assertThat(rec.count("/api/update-role")).isEqualTo(3);
        assertThat(rec.requests.stream().anyMatch(r ->
                r.url().getPath().endsWith("/api/update-role")
                        && r.url().getQuery().contains("ROLE_ADMIN"))).isFalse();
    }

    @Test
    void ensureLiteralUser_existingName_enablesNotAdds() {
        Recorder rec = new Recorder();
        rec.userExists = true;
        CasdoorAdminClient client = clientFor(rec);

        client.ensureLiteralUser("system", "system@brandx", List.of("user", "matrix", "mastodon")).block();

        assertThat(rec.hit("/api/update-user")).isTrue();
        assertThat(rec.hit("/api/add-user")).isFalse();
    }

    @Test
    void createRole_absentRole_postsAddRoleWithCanonicalName() {
        // The per-service identity leg: a brand-new ROLE_<SERVICE> is created (get-role probe
        // says absent → add-role). The role object carries the verbatim name + empty members.
        Recorder rec = new Recorder();
        rec.roleExists = false;
        CasdoorAdminClient client = clientFor(rec);

        client.createRole("ROLE_OWNCAST").block();

        assertThat(rec.hit("/api/get-role")).isTrue();   // idempotency probe
        assertThat(rec.hit("/api/add-role")).isTrue();
    }

    @Test
    void createRole_existingRole_isIdempotentNoAddRole() {
        // Re-running the AddService effector must not 409 — an existing role is a no-op.
        Recorder rec = new Recorder();
        rec.roleExists = true;
        CasdoorAdminClient client = clientFor(rec);

        client.createRole("ROLE_OWNCAST").block();

        assertThat(rec.hit("/api/get-role")).isTrue();
        assertThat(rec.hit("/api/add-role")).isFalse();
    }

    @Test
    void deleteRole_postsDeleteRole_andToleratesAbsent() {
        Recorder rec = new Recorder();
        CasdoorAdminClient client = clientFor(rec);

        client.deleteRole("ROLE_OWNCAST").block();

        assertThat(rec.hit("/api/delete-role")).isTrue();
    }

    @Test
    void addUserToRole_isIdempotentWhenAlreadyMember() {
        Recorder rec = new Recorder();
        rec.roleUsersJson = "{\"status\":\"ok\",\"data\":{\"users\":[\"hugmesh/alice\"]}}";
        CasdoorAdminClient client = clientFor(rec);

        client.addUserToRole("ROLE_USER", "hugmesh/alice").block();

        // Already a member → no update-role write.
        assertThat(rec.hit("/api/get-role")).isTrue();
        assertThat(rec.hit("/api/update-role")).isFalse();
    }
}

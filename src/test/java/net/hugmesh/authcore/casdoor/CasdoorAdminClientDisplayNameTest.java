package net.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Registration displayName leg — {@link CasdoorAdminClient#updateDisplayName}. Asserts the
 * sibling-preserving GET-then-MERGE + {@code &columns=display_name} contract: ONLY the
 * {@code displayName} column is overwritten; every other user column + sibling Property is
 * round-tripped untouched, the same way the MFA-property write behaves.
 *
 * <p>Driven by a body-materializing {@link ExchangeFunction} so the test reads the actual
 * serialized {@code update-user} JSON (no live Casdoor) — copied from
 * {@code CasdoorAdminClientMfaPropertyTest}.
 */
class CasdoorAdminClientDisplayNameTest {

    /** Replies with a canned user object on get-user; captures the serialized body + query
     *  of the update-user POST. */
    static class Recorder implements ExchangeFunction {
        final List<String> updateUserBodies = new ArrayList<>();
        final List<String> updateUserQueries = new ArrayList<>();
        /** The existing user object returned by get-user (columns + siblings to preserve). */
        String getUserJson = "{\"status\":\"ok\",\"data\":{"
                + "\"owner\":\"hugmesh\",\"name\":\"alice\",\"email\":\"alice@x.com\","
                + "\"displayName\":\"alice\",\"isAdmin\":true,"
                + "\"properties\":{\"sibling\":\"keep-me\"}}}";
        boolean userAbsent = false;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            String path = request.url().getPath();
            if (path.endsWith("/api/get-user")) {
                String body = userAbsent ? "{\"status\":\"error\",\"data\":null}" : getUserJson;
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json").body(body).build());
            }
            if (path.endsWith("/api/update-user")) {
                updateUserQueries.add(request.url().getQuery() == null ? "" : request.url().getQuery());
                MockClientHttpRequest mock = new MockClientHttpRequest(request.method(), request.url());
                request.body().insert(mock, new BodyInsertContext()).block();
                updateUserBodies.add(mock.getBodyAsString().block());
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
    }

    /** Minimal BodyInserter context backed by the default client exchange strategies. */
    static class BodyInsertContext implements org.springframework.web.reactive.function.BodyInserter.Context {
        private final ExchangeStrategies strategies = ExchangeStrategies.withDefaults();
        @Override public List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
            return strategies.messageWriters();
        }
        @Override public java.util.Optional<org.springframework.http.server.reactive.ServerHttpRequest> serverRequest() {
            return java.util.Optional.empty();
        }
        @Override public java.util.Map<String, Object> hints() {
            return java.util.Collections.emptyMap();
        }
    }

    private CasdoorAdminClient clientFor(Recorder rec) {
        WebClient web = WebClient.builder().exchangeFunction(rec).build();
        return new CasdoorAdminClient(web, "hugmesh", "app-admin-bff");
    }

    @Test
    void updateDisplayName_setsDisplayNameColumn_preservesOtherColumnsAndSiblings() {
        Recorder rec = new Recorder();
        // google handle "alice@x.com" derives the localpart username "alice" (usernameOf).
        clientFor(rec).updateDisplayName("google", "alice@x.com", "Alice Liddell").block();

        assertThat(rec.updateUserQueries).hasSize(1);
        // The load-bearing &columns=display_name param restricts the write to the displayName column.
        assertThat(rec.updateUserQueries.get(0)).contains("columns=display_name");
        assertThat(rec.updateUserQueries.get(0)).contains("id=hugmesh/alice");

        String body = rec.updateUserBodies.get(0);
        // New human-visible name written.
        assertThat(body).contains("\"displayName\":\"Alice Liddell\"");
        // Other user columns NOT clobbered (round-tripped from get-user).
        assertThat(body).contains("\"isAdmin\":true");
        assertThat(body).contains("\"name\":\"alice\"");
        assertThat(body).contains("\"email\":\"alice@x.com\"");
        // Sibling Property preserved.
        assertThat(body).contains("\"sibling\":\"keep-me\"");
    }

    @Test
    void updateDisplayName_discordHandleDerivesUsernameVerbatim() {
        Recorder rec = new Recorder();
        // discord handle is used verbatim as the username (usernameOf).
        clientFor(rec).updateDisplayName("discord", "bob", "Bob B").block();
        assertThat(rec.updateUserQueries.get(0)).contains("id=hugmesh/bob");
        assertThat(rec.updateUserBodies.get(0)).contains("\"displayName\":\"Bob B\"");
    }

    @Test
    void blankDisplayName_noOp() {
        Recorder rec = new Recorder();
        clientFor(rec).updateDisplayName("google", "alice@x.com", "   ").block();
        clientFor(rec).updateDisplayName("google", "alice@x.com", null).block();
        assertThat(rec.updateUserBodies).isEmpty();
    }

    @Test
    void absentUser_noUpdate_bestEffort() {
        Recorder rec = new Recorder();
        rec.userAbsent = true;
        // Best-effort: an absent user is a no-op (no update-user), never an error.
        clientFor(rec).updateDisplayName("google", "ghost@x.com", "Ghost").block();
        assertThat(rec.updateUserBodies).isEmpty();
    }
}

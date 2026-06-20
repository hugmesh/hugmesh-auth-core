package systems.snapdragon.authcore.casdoor;

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
 * D8 A4 ADVISORY leg — {@link CasdoorAdminClient#writeMfaProperty} /
 * {@link CasdoorAdminClient#clearMfaProperty}. Asserts the load-bearing GET-then-MERGE +
 * {@code &columns=properties} contract: the MFA Property is set/removed WITHOUT clobbering
 * sibling Properties or the user's other columns (isAdmin / name / email).
 *
 * <p>Driven by a body-materializing {@link ExchangeFunction} so the test reads the actual
 * serialized {@code update-user} JSON (no live Casdoor).
 */
class CasdoorAdminClientMfaPropertyTest {

    /** Replies with a canned user object on get-user; captures the serialized body + query
     *  of the update-user POST. */
    static class Recorder implements ExchangeFunction {
        final List<String> updateUserBodies = new ArrayList<>();
        final List<String> updateUserQueries = new ArrayList<>();
        /** The existing user object returned by get-user (siblings to preserve). */
        String getUserJson = "{\"status\":\"ok\",\"data\":{"
                + "\"owner\":\"snapdragon\",\"name\":\"alice\",\"email\":\"alice@x.com\","
                + "\"isAdmin\":true,"
                + "\"properties\":{\"sibling\":\"keep-me\",\"mfa_satisfied_at\":\"111\"}}}";
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
                // Materialize the request body to a string.
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
        return new CasdoorAdminClient(web, "snapdragon", "app-admin-bff");
    }

    @Test
    void writeMfaProperty_setsMfaKey_preservesSiblingsAndColumns() {
        Recorder rec = new Recorder();
        clientFor(rec).writeMfaProperty("alice", 1_750_000_000_000L).block();

        assertThat(rec.updateUserQueries).hasSize(1);
        // The load-bearing &columns=properties param restricts the write to the properties column.
        assertThat(rec.updateUserQueries.get(0)).contains("columns=properties");
        assertThat(rec.updateUserQueries.get(0)).contains("id=snapdragon/alice");

        String body = rec.updateUserBodies.get(0);
        // New MFA stamp written as a NUMERIC STRING.
        assertThat(body).contains("\"mfa_satisfied_at\":\"1750000000000\"");
        // Sibling Property preserved.
        assertThat(body).contains("\"sibling\":\"keep-me\"");
        // Other user columns NOT clobbered (round-tripped from get-user).
        assertThat(body).contains("\"isAdmin\":true");
        assertThat(body).contains("\"name\":\"alice\"");
        assertThat(body).contains("\"email\":\"alice@x.com\"");
    }

    @Test
    void clearMfaProperty_removesMfaKey_preservesSiblings() {
        Recorder rec = new Recorder();
        clientFor(rec).clearMfaProperty("alice").block();

        assertThat(rec.updateUserQueries.get(0)).contains("columns=properties");
        String body = rec.updateUserBodies.get(0);
        // The MFA key is gone but the sibling stays.
        assertThat(body).doesNotContain("mfa_satisfied_at");
        assertThat(body).contains("\"sibling\":\"keep-me\"");
    }

    @Test
    void absentUser_noUpdate_bestEffort() {
        Recorder rec = new Recorder();
        rec.userAbsent = true;
        // Best-effort: an absent user is a no-op (no update-user), never an error.
        clientFor(rec).writeMfaProperty("ghost", 123L).block();
        assertThat(rec.updateUserBodies).isEmpty();
    }

    @Test
    void blankUsername_noOp() {
        Recorder rec = new Recorder();
        clientFor(rec).writeMfaProperty("  ", 123L).block();
        clientFor(rec).clearMfaProperty(null).block();
        assertThat(rec.updateUserBodies).isEmpty();
    }
}

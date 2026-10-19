package net.hugmesh.authcore.account;

import com.sun.net.httpserver.HttpServer;
import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.authcore.casdoor.OidcExchangeClient;
import net.hugmesh.authcore.casdoor.OidcTokens;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The login path owned by this jar, end to end on ONE path (hugmesh-auth-core issue #4):
 * {@link OidcExchangeClient} over a real HTTP socket to a stand-in Casdoor token endpoint →
 * {@link AccountStore#ensureAccount} → {@link AccountStore#newSession} → {@link BffCustodyCipher}
 * encrypting the tokens → {@link AccountStore#stampCustody} → resolve / refresh / logout, all
 * through the real repositories over an R2DBC-H2 store.
 *
 * <p>Each collaborator already has its own unit or slice test; none of those would fail if the
 * collaborators stopped fitting together (a mocked repository cannot disagree with the facade,
 * a stubbed {@code ExchangeFunction} never reaches a socket). This class covers the seams.
 *
 * <p>Out of scope here, because it is not owned by this jar: the gateway's exchange-filter
 * ({@code /bff/session} introspection through {@code BffSessionAuthFilter}) and the browser
 * leg, which the generator's kind harness drives.
 */
@DataR2dbcTest
@Import({SsoFlowTestDatabaseConfig.class})
// Own context-cache key so this class gets its own H2 database (see AllowlistTestDatabaseConfig).
@TestPropertySource(properties = "authcore.test.slice=sso-flow")
class SsoFlowTest {

    private static final String TOKEN_PATH = "/api/login/oauth/access_token";
    private static final String REDIRECT = "https://hugmesh.test/login/callback";

    /** One token-endpoint request as the stand-in IdP saw it: decoded form fields. */
    private record Seen(String method, String contentType, Map<String, String> form) { }

    private static HttpServer idp;
    private static String idpBase;
    private static final List<Seen> seen = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void startIdp() throws IOException {
        idp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        idp.createContext(TOKEN_PATH, exchange -> {
            String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = new HashMap<>();
            for (String pair : raw.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                }
            }
            seen.add(new Seen(exchange.getRequestMethod(),
                    exchange.getRequestHeaders().getFirst("Content-Type"), form));

            String grant = form.get("grant_type");
            String body;
            int status = 200;
            if ("authorization_code".equals(grant)
                    && "good-code".equals(form.get("code"))
                    && "good-verifier".equals(form.get("code_verifier"))
                    && "user-bff".equals(form.get("client_id"))
                    && "s3cret".equals(form.get("client_secret"))
                    && REDIRECT.equals(form.get("redirect_uri"))) {
                body = "{\"access_token\":\"AT-1\",\"refresh_token\":\"RT-1\","
                        + "\"id_token\":\"ID-1\",\"expires_in\":1200}";
            } else if ("refresh_token".equals(grant) && "RT-1".equals(form.get("refresh_token"))) {
                body = "{\"access_token\":\"AT-2\",\"refresh_token\":\"RT-2\",\"expires_in\":600}";
            } else {
                status = 400;
                body = "{\"error\":\"invalid_grant\"}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        idp.start();
        idpBase = "http://127.0.0.1:" + idp.getAddress().getPort();
    }

    @AfterAll
    static void stopIdp() {
        idp.stop(0);
    }

    @BeforeEach
    void reset() {
        seen.clear();
    }

    @Autowired AllowlistRepository allowlist;
    @Autowired AccountRowRepository accounts;
    @Autowired BffSessionRepository sessions;
    @Autowired NamespaceGrantRepository grants;

    private final BffCustodyCipher cipher = new BffCustodyCipher("sso-flow-test-custody-key");

    private AccountStore store() {
        return new AccountStore(allowlist, accounts, sessions, grants, "");
    }

    private static OidcExchangeClient idpClient() {
        return new OidcExchangeClient(idpBase, TOKEN_PATH, "user-bff", "s3cret", 3600L);
    }

    /** The native-login composition: code exchange, account sync, session mint, custody stamp. */
    private Mono<String> login(AccountStore store, String handle, List<String> roles) {
        return idpClient().exchangeCode("good-code", "good-verifier", REDIRECT)
                .flatMap(t -> store.ensureAccount("casdoor", handle, roles)
                        .flatMap(store::newSession)
                        .flatMap(token -> store.stampCustody(token,
                                        cipher.encrypt(t.accessToken()),
                                        cipher.encrypt(t.refreshToken()),
                                        LocalDateTime.now().plusSeconds(t.expiresInSeconds()))
                                .thenReturn(token)));
    }

    @Test
    void codeExchangeToSession_resolvesTheAccount_andHoldsOnlyEncryptedTokens() {
        AccountStore store = store();

        String token = login(store, "Alice", List.of("user", "admin")).block();

        assertThat(token).startsWith("bff_");
        // The IdP got the PKCE verifier and the client credentials as a form POST.
        assertThat(seen).hasSize(1);
        assertThat(seen.get(0).method()).isEqualTo("POST");
        assertThat(seen.get(0).contentType()).startsWith("application/x-www-form-urlencoded");
        assertThat(seen.get(0).form()).containsEntry("grant_type", "authorization_code")
                .containsEntry("code_verifier", "good-verifier");

        // The opaque session resolves back to the account the exchange created.
        StepVerifier.create(store.sessionOf("Bearer " + token))
                .assertNext(a -> {
                    assertThat(a.id()).isEqualTo("casdoor:alice");
                    assertThat(a.roles()).containsExactly("user", "admin");
                })
                .verifyComplete();

        // Custody columns hold ciphertext, never the plaintext tokens, and decrypt back.
        BffSession row = store.sessionRow(token).block();
        assertThat(row.accessTokenEnc()).isNotBlank().isNotEqualTo("AT-1");
        assertThat(row.refreshTokenEnc()).isNotBlank().isNotEqualTo("RT-1");
        assertThat(cipher.decrypt(row.accessTokenEnc())).isEqualTo("AT-1");
        assertThat(cipher.decrypt(row.refreshTokenEnc())).isEqualTo("RT-1");
        assertThat(row.accessTokenExpiresAt()).isAfter(LocalDateTime.now().plusSeconds(1000));
        assertThat(row.accessTokenExpiresAt()).isBefore(LocalDateTime.now().plusSeconds(1300));
        // Custody is stamped on top of the mint; it never marks MFA satisfied.
        assertThat(row.mfaSatisfied()).isFalse();
    }

    @Test
    void refreshLeg_usesTheHeldRefreshToken_andRestampsWithoutDisturbingTheSession() {
        AccountStore store = store();
        String token = login(store, "bob", List.of("user")).block();
        store.stampMfaSatisfied(token, "pwd,otp").block();
        seen.clear();

        // What the exchange endpoint does when the held access token is about to expire.
        BffSession held = store.sessionRow(token).block();
        OidcTokens fresh = idpClient().refresh(cipher.decrypt(held.refreshTokenEnc())).block();
        store.stampCustody(token, cipher.encrypt(fresh.accessToken()),
                cipher.encrypt(fresh.refreshToken()),
                LocalDateTime.now().plusSeconds(fresh.expiresInSeconds())).block();

        assertThat(seen).hasSize(1);
        assertThat(seen.get(0).form()).containsEntry("grant_type", "refresh_token")
                .containsEntry("refresh_token", "RT-1");

        BffSession after = store.sessionRow(token).block();
        assertThat(cipher.decrypt(after.accessTokenEnc())).isEqualTo("AT-2");
        assertThat(cipher.decrypt(after.refreshTokenEnc())).isEqualTo("RT-2");
        // The partial-column restamp left the lifecycle and MFA columns alone.
        assertThat(after.accountId()).isEqualTo("casdoor:bob");
        assertThat(after.expiresAt()).isEqualTo(held.expiresAt());
        assertThat(after.mfaSatisfied()).isTrue();
        assertThat(after.amr()).isEqualTo("pwd,otp");
        StepVerifier.create(store.sessionOfToken(token)).expectNextCount(1).verifyComplete();
    }

    @Test
    void logout_removesOnlyThatSession_andItsCustodyWithIt() {
        AccountStore store = store();
        String first = login(store, "carol", List.of("user")).block();
        String second = login(store, "carol", List.of("user")).block();
        assertThat(first).isNotEqualTo(second);
        StepVerifier.create(store.sessionsForAccount("casdoor:carol").collectList())
                .assertNext(l -> assertThat(l).hasSize(2)).verifyComplete();

        StepVerifier.create(store.deleteSession(first)).expectNext("casdoor:carol").verifyComplete();

        StepVerifier.create(store.sessionOfToken(first)).verifyComplete();
        StepVerifier.create(store.sessionRow(first)).verifyComplete();
        StepVerifier.create(store.sessionOfToken(second)).expectNextCount(1).verifyComplete();
        assertThat(cipher.decrypt(store.sessionRow(second).block().accessTokenEnc())).isEqualTo("AT-1");
        StepVerifier.create(store.sessionsForAccount("casdoor:carol").collectList())
                .assertNext(l -> assertThat(l).hasSize(1)).verifyComplete();
    }

    @Test
    void rejectedCodeExchange_mintsNoAccountAndNoSession() {
        AccountStore store = store();

        Mono<String> attempt = idpClient().exchangeCode("good-code", "WRONG-verifier", REDIRECT)
                .flatMap(t -> store.ensureAccount("casdoor", "mallory", List.of("user"))
                        .flatMap(store::newSession));

        StepVerifier.create(attempt).expectError().verify();
        assertThat(seen).hasSize(1);
        StepVerifier.create(store.account("casdoor:mallory")).verifyComplete();
        StepVerifier.create(store.sessionsForAccount("casdoor:mallory")).verifyComplete();
    }

    @Test
    void roleChangeAtTheIdp_reachesAnAlreadyIssuedSession_onTheNextLogin() {
        AccountStore store = store();
        String old = login(store, "dave", List.of("user", "admin")).block();

        String fresh = login(store, "dave", List.of("user")).block();

        // Same human, same account row: the earlier session now sees the synced roles.
        StepVerifier.create(store.sessionOfToken(old))
                .assertNext(a -> assertThat(a.roles()).containsExactly("user")).verifyComplete();
        StepVerifier.create(store.sessionOfToken(fresh))
                .assertNext(a -> assertThat(a.id()).isEqualTo("casdoor:dave")).verifyComplete();
    }
}

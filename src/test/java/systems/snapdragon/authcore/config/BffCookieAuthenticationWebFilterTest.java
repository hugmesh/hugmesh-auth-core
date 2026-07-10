package systems.snapdragon.authcore.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.authcore.account.Account;
import systems.snapdragon.authcore.account.AccountStore;
import systems.snapdragon.authcore.account.AccountStore.MfaState;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit contract for {@link BffCookieAuthenticationWebFilter} — the service-local
 * counterpart to the gateway's {@code BffSessionAuthFilter}, mirrored test-for-test
 * against {@code BffSessionAuthFilterTest} (snapdragon-gateway) where the behaviour
 * overlaps (authority mapping, token extraction, pass-through rules), but resolving
 * sessions via a mocked {@link AccountStore} instead of a mocked WebClient/HTTP hop.
 */
class BffCookieAuthenticationWebFilterTest {

    /** Wraps a (possibly-null) {@link AccountStore} into the {@link ObjectProvider}
     *  the filter's constructor now takes, mirroring how Spring resolves it lazily
     *  per-request rather than as a hard constructor dependency. */
    @SuppressWarnings("unchecked")
    private static ObjectProvider<AccountStore> providerOf(AccountStore store) {
        ObjectProvider<AccountStore> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(store);
        return provider;
    }

    /** Captures the Authentication present in the downstream SecurityContext, and — critically —
     *  COUNTS invocations rather than just flagging a boolean: a filter bug that calls
     *  {@code chain.filter(exchange)} twice (e.g. a stray {@code switchIfEmpty} after a
     *  {@code Mono<Void>}-returning flatMap, which is ALWAYS "empty" since Void never emits
     *  onNext) would look identical to a single call under a boolean flag, but doubles the
     *  downstream side effects and fails once the response is already committed in production. */
    private static final class CapturingChain implements WebFilterChain {
        final AtomicInteger forwarded = new AtomicInteger(0);
        final AtomicReference<Authentication> auth = new AtomicReference<>();

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.incrementAndGet();
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .doOnNext(auth::set)
                    .then();
        }
    }

    // ── happy path ─────────────────────────────────────────────────────────────

    @Test
    void validBffToken_populatesSecurityContext() {
        Account account = new Account("google:user@example.com", "google", "user@example.com", true,
                List.of("user", "admin"));
        AccountStore accounts = mock(AccountStore.class);
        when(accounts.sessionOfToken("bff_abc123")).thenReturn(Mono.just(account));
        when(accounts.mfaStateOf("bff_abc123")).thenReturn(Mono.just(new MfaState(false, null)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().isAuthenticated()).isTrue();
        assertThat(chain.auth.get().getName()).isEqualTo("google:user@example.com");

        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    // ── no bff_ token: Casdoor JWT bearer → pass-through, no AccountStore call ──

    @Test
    void casdoorJwtBearer_isNotABffToken_passesThrough_withoutCallingAccountStore() {
        AccountStore accounts = mock(AccountStore.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9....")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(accounts, never()).sessionOfToken(org.mockito.ArgumentMatchers.anyString());
    }

    // ── no token at all → pass-through ──────────────────────────────────────────

    @Test
    void noToken_passesThrough_unauthenticated() {
        AccountStore accounts = mock(AccountStore.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(accounts, never()).sessionOfToken(org.mockito.ArgumentMatchers.anyString());
    }

    // ── unknown/expired bff_ token → pass-through unauthenticated (never a floor grant) ──

    @Test
    void unknownToken_passesThrough_unauthenticated() {
        AccountStore accounts = mock(AccountStore.class);
        when(accounts.sessionOfToken("bff_expired")).thenReturn(Mono.empty());

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_expired")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
    }

    // ── no AccountStore bean available (e.g. a slice-test context) → pass-through ──

    @Test
    void noAccountStoreAvailable_passesThrough_unauthenticated() {
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(null));

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
    }

    // ── incomplete registration → restricted authority set ──────────────────────

    @Test
    void incompleteRegistration_onlyRoleUser_noAdminAuthority() {
        Account account = new Account("google:newuser", "google", "newuser", false, List.of("user", "admin"));
        AccountStore accounts = mock(AccountStore.class);
        when(accounts.sessionOfToken("bff_newusertoken")).thenReturn(Mono.just(account));
        when(accounts.mfaStateOf("bff_newusertoken")).thenReturn(Mono.just(new MfaState(false, null)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_newusertoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    // ── MFA satisfied / not satisfied ────────────────────────────────────────────

    @Test
    void mfaSatisfied_addsMfaSatisfiedAuthority() {
        Account account = new Account("google:mfauser", "google", "mfauser", true, List.of("user", "admin"));
        AccountStore accounts = mock(AccountStore.class);
        when(accounts.sessionOfToken("bff_mfatoken")).thenReturn(Mono.just(account));
        when(accounts.mfaStateOf("bff_mfatoken")).thenReturn(Mono.just(new MfaState(true, LocalDateTime.now())));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/sensitive")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_mfatoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).contains("MFA_SATISFIED", "ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void mfaStateEmpty_treatedAsNotSatisfied() {
        // mfaStateOf() returns Mono.empty() for a session with no MFA row at all.
        Account account = new Account("google:user", "google", "user", true, List.of("user"));
        AccountStore accounts = mock(AccountStore.class);
        when(accounts.sessionOfToken("bff_nomfarow")).thenReturn(Mono.just(account));
        when(accounts.mfaStateOf("bff_nomfarow")).thenReturn(Mono.empty());

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_nomfarow")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).doesNotContain("MFA_SATISFIED");
    }

    // ── authority mapping unit tests ─────────────────────────────────────────────

    @Test
    void buildAuthorities_rolesMappedToUppercase_withFloor() {
        Account account = new Account("google:admin", "google", "admin", true, List.of("user", "admin", "mod"));
        var authorities = BffCookieAuthenticationWebFilter.buildAuthorities(account, false).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void buildAuthorities_roleUserInAccountRoles_notDuplicated() {
        Account account = new Account("google:u", "google", "u", true, List.of("user"));
        var authorities = BffCookieAuthenticationWebFilter.buildAuthorities(account, false).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    void buildAuthorities_superadmin_isMapped() {
        Account account = new Account("google:sa", "google", "sa", true, List.of("superadmin"));
        var authorities = BffCookieAuthenticationWebFilter.buildAuthorities(account, false).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).contains("ROLE_SUPERADMIN", "ROLE_USER");
    }

    @Test
    void buildAuthorities_nullRoles_onlyFloor() {
        Account account = new Account("google:norow", "google", "norow", true, null);
        var authorities = BffCookieAuthenticationWebFilter.buildAuthorities(account, false).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }

    // ── token extraction (via full filter invocation, since extractToken is private) ──

    @Test
    void bearerNonBffToken_notExtracted_noAccountStoreCall() {
        AccountStore accounts = mock(AccountStore.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(accounts));

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/admin/usage")
                .header(HttpHeaders.AUTHORIZATION, "not-even-bearer bff_abc123")
                .build();
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(MockServerWebExchange.from(req), chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(accounts, never()).sessionOfToken(org.mockito.ArgumentMatchers.anyString());
    }
}

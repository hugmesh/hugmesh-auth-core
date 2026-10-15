package net.hugmesh.authcore.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Contract of {@link BffSessionIntrospectionWebFilter}, the HTTP-resolved session bridge. */
class BffSessionIntrospectionWebFilterTest {

    private static final class CapturingChain implements WebFilterChain {
        final AtomicInteger forwarded = new AtomicInteger();
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

    private static final class CountingIntrospector implements BffSessionIntrospector {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<String> lastToken = new AtomicReference<>();
        private final java.util.function.Function<String, Mono<BffSessionIntrospection>> impl;

        CountingIntrospector(java.util.function.Function<String, Mono<BffSessionIntrospection>> impl) {
            this.impl = impl;
        }

        @Override
        public Mono<BffSessionIntrospection> introspect(String bffToken) {
            calls.incrementAndGet();
            lastToken.set(bffToken);
            return impl.apply(bffToken);
        }
    }

    private static MockServerWebExchange exchangeWith(String authorization) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get("/bff/mod/queue");
        if (authorization != null) b.header(HttpHeaders.AUTHORIZATION, authorization);
        return MockServerWebExchange.from(b.build());
    }

    private static BffSessionIntrospectionWebFilter filterOver(CountingIntrospector i) {
        return new BffSessionIntrospectionWebFilter(i, Duration.ofMillis(500));
    }

    private static BffSessionIntrospection intro(String status, boolean registrationComplete,
                                                 boolean mfa, String... roles) {
        return new BffSessionIntrospection("google:u@example.com", "google", List.of(roles),
                registrationComplete, status, mfa);
    }

    @Test
    void activeSession_authenticatesWithMappedAuthorities_andRunsChainOnce() {
        var i = new CountingIntrospector(t -> Mono.just(intro("active", true, true, "user", "moderator")));
        var chain = new CapturingChain();
        var ex = exchangeWith("Bearer bff_abc");

        filterOver(i).filter(ex, chain).block();

        assertThat(i.lastToken.get()).isEqualTo("bff_abc");
        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get().getName()).isEqualTo("google:u@example.com");
        assertThat(chain.auth.get().getAuthorities()).extracting(Object::toString)
                .containsExactly("ROLE_USER", "ROLE_MODERATOR", "MFA_SATISFIED");
    }

    @Test
    void incompleteRegistration_getsOnlyTheUserFloor() {
        var i = new CountingIntrospector(t -> Mono.just(intro("active", false, true, "admin")));
        var chain = new CapturingChain();

        filterOver(i).filter(exchangeWith("Bearer bff_abc"), chain).block();

        assertThat(chain.auth.get().getAuthorities()).extracting(Object::toString)
                .containsExactly("ROLE_USER");
    }

    @Test
    void unknownSession_passesThroughUnauthenticated() {
        var i = new CountingIntrospector(t -> Mono.empty());
        var chain = new CapturingChain();
        var ex = exchangeWith("Bearer bff_gone");

        filterOver(i).filter(ex, chain).block();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        assertThat(ex.getResponse().getStatusCode()).isNull();
    }

    @Test
    void jwtOrAbsentHeader_neverCallsTheIntrospector() {
        var i = new CountingIntrospector(t -> Mono.just(intro("active", true, false)));
        var chain = new CapturingChain();

        filterOver(i).filter(exchangeWith("Bearer eyJhbGciOi.jwt.sig"), chain).block();
        filterOver(i).filter(exchangeWith(null), chain).block();

        assertThat(i.calls.get()).isZero();
        assertThat(chain.forwarded.get()).isEqualTo(2);
    }

    @Test
    void bannedAndSuspended_are403WithDeniedHeader_andNeverReachTheChain() {
        for (String status : List.of("banned", "SUSPENDED")) {
            var i = new CountingIntrospector(t -> Mono.just(intro(status, true, true, "admin")));
            var chain = new CapturingChain();
            var ex = exchangeWith("Bearer bff_abc");

            filterOver(i).filter(ex, chain).block();

            assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(ex.getResponse().getHeaders().getFirst(BffSessionIntrospectionWebFilter.DENIED_HEADER))
                    .isEqualTo("account-" + status.toLowerCase());
            assertThat(chain.forwarded.get()).isZero();
        }
    }

    @Test
    void unknownMissingOrMalformedStatus_is403WithConstantReason_andNeverReachesTheChain() {
        // null = the introspect body omitted the field (the record no longer defaults it to active).
        for (String status : java.util.Arrays.asList(null, "", "   ", "pending", "disabled", "locked",
                " active", "active ", "active\n", "activ", "ac\u0074ive\u200b", "active\r\nX-Evil: 1")) {
            var i = new CountingIntrospector(t -> Mono.just(intro(status, true, true, "admin")));
            var chain = new CapturingChain();
            var ex = exchangeWith("Bearer bff_abc");

            filterOver(i).filter(ex, chain).block();

            assertThat(ex.getResponse().getStatusCode()).as("status=%s", status).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(ex.getResponse().getHeaders().getFirst(BffSessionIntrospectionWebFilter.DENIED_HEADER))
                    .as("status=%s", status).isEqualTo("account-status-unrecognized");
            assertThat(ex.getResponse().getHeaders().containsKey("X-Evil")).isFalse();
            assertThat(chain.forwarded.get()).as("status=%s", status).isZero();
        }
    }

    @Test
    void activeInAnyCase_stillAuthenticates() {
        for (String status : List.of("active", "ACTIVE", "Active")) {
            var i = new CountingIntrospector(t -> Mono.just(intro(status, true, false, "user")));
            var chain = new CapturingChain();

            filterOver(i).filter(exchangeWith("Bearer bff_abc"), chain).block();

            assertThat(chain.forwarded.get()).as("status=%s", status).isEqualTo(1);
            assertThat(chain.auth.get()).as("status=%s", status).isNotNull();
        }
    }

    @Test
    void introspectorError_failsClosedWith503_andNeverReachesTheChain() {
        var i = new CountingIntrospector(t -> Mono.error(new IllegalStateException("admin-bff down")));
        var chain = new CapturingChain();
        var ex = exchangeWith("Bearer bff_abc");

        filterOver(i).filter(ex, chain).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(chain.forwarded.get()).isZero();
    }

    @Test
    void introspectorTimeout_failsClosedWith503() {
        var i = new CountingIntrospector(t -> Mono.never());
        var chain = new CapturingChain();
        var ex = exchangeWith("Bearer bff_abc");

        new BffSessionIntrospectionWebFilter(i, Duration.ofMillis(50)).filter(ex, chain).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(chain.forwarded.get()).isZero();
    }

    @Test
    void downstreamFailure_isNotSwallowedIntoA503() {
        var i = new CountingIntrospector(t -> Mono.just(intro("active", true, false)));
        WebFilterChain failing = e -> Mono.error(new IllegalArgumentException("handler blew up"));
        var ex = exchangeWith("Bearer bff_abc");

        try {
            filterOver(i).filter(ex, failing).block();
            org.junit.jupiter.api.Assertions.fail("expected the handler failure to propagate");
        } catch (IllegalArgumentException expected) {
            assertThat(ex.getResponse().getStatusCode()).isNull();
        }
    }
}

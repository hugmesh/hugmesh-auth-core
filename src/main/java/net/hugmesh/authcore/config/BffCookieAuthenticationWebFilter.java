package net.hugmesh.authcore.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * A3 SERVICE-LOCAL BFF SESSION AUTHENTICATION — bridges an opaque {@code bff_}
 * session token (normalised into the {@code Authorization} header by {@link
 * SessionCookieWebFilter}, whichever carrier it originally arrived in) into a
 * REAL Spring Security {@link org.springframework.security.core.Authentication},
 * so declarative {@code hasAnyRole()}/{@code hasRole()}/{@code .authenticated()}
 * gates in each service's OWN {@code SecurityConfig} can see it.
 *
 * <h3>Why this exists</h3>
 * The gateway's own {@code BffSessionAuthFilter} (hugmesh-gateway) authenticates
 * a bff_ session AT THE GATEWAY, for the gateway's OWN route-access decision — but
 * that authentication is local to the gateway's request-processing context; HTTP
 * carries no equivalent for a downstream service to consume automatically.
 * {@link SessionCookieWebFilter} only NORMALISES the token's carrier into the
 * {@code Authorization} header, for MANUALLY header-reading controllers (like the
 * legacy {@code /bff/me}); it never touches Spring Security's own authentication.
 * Each service's {@code oauth2ResourceServer().jwt(...)} config is (correctly)
 * inert to a non-JWT bff_ token — so, until this filter, NOTHING ever authenticated
 * a bff_-cookie-only request against a service's OWN {@code hasAnyRole()}/
 * {@code .authenticated()} gate: it was architecturally unreachable via native
 * login, regardless of what the gateway itself decided. Found live 2026-07
 * testing admin-ui's real per-role pages end-to-end (not just gateway-level
 * route-access) for the first time — the gateway's route-access DB correctly
 * granted the request through, but the service's OWN security still 401'd it.
 *
 * <h3>Trust</h3>
 * A bff_ token is an opaque, DB-backed session id (not a decodable/forgeable
 * value) — {@link AccountStore#sessionOfToken(String)} resolves it against the
 * SAME session table the gateway's own introspection endpoint reads, so
 * authenticating from a successful lookup here is exactly as trustworthy as the
 * gateway's own bridge, just done locally (this service owns the DB directly —
 * no extra network hop needed, unlike the gateway which must call over HTTP).
 *
 * <h3>Authority mapping</h3>
 * Mirrors the gateway's {@code BffSessionAuthFilter.buildAuthorities}: ROLE_USER
 * floor always granted; if {@code registrationComplete} is false, ONLY the floor
 * (an incomplete registration cannot satisfy any elevated role, though it can
 * still reach {@code permitAll()}/{@code .authenticated()} registration
 * endpoints); otherwise each role maps to {@code ROLE_<UPPER>}, deduplicated
 * against the floor; {@code MFA_SATISFIED} is added when the session's MFA
 * step-up is stamped.
 *
 * <h3>Ordering</h3>
 * Runs at {@code HIGHEST_PRECEDENCE + 10} — after {@link SessionCookieWebFilter}
 * ({@code +5}, so the header is already normalised) and before Spring Security's
 * own {@code AUTHENTICATION} filter slot, so a populated SecurityContext here
 * short-circuits the (inert-anyway) JWT resource-server attempt.
 *
 * <h3>Non-interference with JWT auth</h3>
 * Skips entirely (passes through unchanged) when the {@code Authorization}
 * header is absent or does not carry a {@code bff_} token — a real Casdoor JWT
 * request is completely untouched by this filter, exactly like the gateway's
 * own filter leaves the JWT path undisturbed. An unknown/expired bff_ token
 * also passes through unauthenticated (never treated as a floor grant) — the
 * service's own {@code anyExchange().authenticated()} rule produces the 401 for
 * protected paths, {@code permitAll()} paths still succeed.
 *
 * <h3>Scope — services with a LOCAL {@link AccountStore} only</h3>
 * This filter resolves a session by calling {@link AccountStore} DIRECTLY, which
 * only works for a service that owns the accounts/bff_session tables itself
 * (today: admin-bff-api). A service without local database access to those tables
 * (network-isolated from them by design) uses {@link BffSessionIntrospectionWebFilter}
 * instead, which resolves the session over HTTP against admin-bff's
 * {@code /bff/internal/session/introspect} endpoint and shares this class's
 * authority mapping.
 *
 * <h3>Tolerating a missing {@link AccountStore} — {@code ObjectProvider}, not
 * {@code @ConditionalOnBean}</h3>
 * Boot's {@code @WebFluxTest} slice auto-includes every {@code WebFilter}-typed
 * bean found by its component scan (the same allowlist that lets a CORS/security
 * filter run in a narrow HTTP-layer slice) — so, if this filter had a hard
 * {@code AccountStore} constructor dependency, it would fail to construct in
 * every one of admin-bff-api's ~67 {@code @WebFluxTest} slices that never
 * {@code @MockitoBean} an {@code AccountStore}, breaking each with a
 * {@code NoSuchBeanDefinitionException}. An earlier version of this class used
 * {@code @ConditionalOnBean(AccountStore.class)} to route around that — but
 * Spring's own docs call that pattern out as unsafe on a plain
 * {@code @Component} (only reliable on {@code @Configuration}/auto-configuration
 * classes): it happened to work here only because {@code account} sorts before
 * {@code config} in this component-scan's package traversal, not because of any
 * guaranteed ordering. Taking {@link ObjectProvider}{@code <AccountStore>}
 * instead removes the ordering dependency entirely — this bean ALWAYS
 * constructs, and {@link ObjectProvider#getIfAvailable()} is resolved lazily,
 * per request, in {@link #filter}. No {@code AccountStore} bean in the context
 * (the common slice-test case) behaves exactly like an absent {@code bff_}
 * token: pass through unauthenticated, identical to today's pre-fix behaviour.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BffCookieAuthenticationWebFilter implements WebFilter {

    /** Authority granted when the MFA challenge has been satisfied for this session.
     *  Matches the gateway's own {@code BffSessionAuthFilter.MFA_SATISFIED} constant. */
    public static final String MFA_SATISFIED = "MFA_SATISFIED";

    private static final String BFF_PREFIX = "bff_";

    private final ObjectProvider<AccountStore> accounts;

    public BffCookieAuthenticationWebFilter(ObjectProvider<AccountStore> accounts) {
        this.accounts = accounts;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        AccountStore store = token == null ? null : accounts.getIfAvailable();
        if (store == null) {
            return chain.filter(exchange);
        }

        Mono<Authentication> resolved = store.sessionOfToken(token)
                .flatMap(account -> store.mfaStateOf(token)
                        .map(mfa -> authenticationFor(account, mfa.satisfied()))
                        .defaultIfEmpty(authenticationFor(account, false)));

        // NOTE: resolved.flatMap(auth -> chain.filter(exchange)...).switchIfEmpty(chain.filter(exchange))
        // looks equivalent but is NOT: chain.filter() returns Mono<Void>, which never emits
        // onNext even when it completes successfully, so switchIfEmpty would ALWAYS see the
        // flatMap's result as "empty" and invoke chain.filter(exchange) a SECOND time on every
        // successful auth — a duplicate downstream execution that fails once the response is
        // already committed (frozen headers). Branching on an Optional<Authentication> first,
        // then calling chain.filter(exchange) from exactly one flatMap arm, avoids that trap.
        return resolved.map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(auth -> auth.isPresent()
                        ? chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth.get()))
                        : chain.filter(exchange));
    }

    /**
     * Extracts a {@code bff_} token from the {@code Authorization} header only —
     * by the time this filter runs ({@code +10}), {@link SessionCookieWebFilter}
     * ({@code +5}) has already normalised whichever original carrier (cookie or
     * header) into this same header, so there is no need to re-read the cookie
     * here.
     */
    private static String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) return null;
        String trimmed = authHeader.trim();
        if (!trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        String candidate = trimmed.substring(7).trim();
        return candidate.startsWith(BFF_PREFIX) ? candidate : null;
    }

    private static UsernamePasswordAuthenticationToken authenticationFor(Account account, boolean mfaSatisfied) {
        return new UsernamePasswordAuthenticationToken(account.id(), null, buildAuthorities(account, mfaSatisfied));
    }

    /** Package-private (not private) so a unit test can exercise the mapping directly. */
    static List<GrantedAuthority> buildAuthorities(Account account, boolean mfaSatisfied) {
        return buildAuthorities(account.registrationComplete(), account.roles(), mfaSatisfied);
    }

    /**
     * The one authority mapping, shared with {@link BffSessionIntrospectionWebFilter} so the
     * local-store filter and the HTTP-bridge filter can never disagree on what a session grants.
     */
    static List<GrantedAuthority> buildAuthorities(boolean registrationComplete, Collection<String> roles,
                                                   boolean mfaSatisfied) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        if (!registrationComplete) {
            return authorities;
        }

        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    String authority = "ROLE_" + role.trim().toUpperCase();
                    if (!"ROLE_USER".equals(authority)) {
                        authorities.add(new SimpleGrantedAuthority(authority));
                    }
                }
            }
        }

        if (mfaSatisfied) {
            authorities.add(new SimpleGrantedAuthority(MFA_SATISFIED));
        }

        return authorities;
    }
}

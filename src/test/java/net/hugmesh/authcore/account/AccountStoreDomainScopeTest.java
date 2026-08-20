package net.hugmesh.authcore.account;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the domain-scoping layer of {@link AccountStore}'s allowlist and
 * namespace-grant methods (changeset 220). Proves that:
 * <ul>
 *   <li>Domain-scoped reads delegate to the domain-filtered repository methods.</li>
 *   <li>Unscoped reads (SUPERADMIN path) delegate to the unfiltered repository methods.</li>
 *   <li>Domain-scoped writes stamp the correct domain on the row.</li>
 *   <li>Domain-scoped deletes pass the domain predicate so cross-tenant deletes are rejected
 *       at the SQL level (the domain column is in the WHERE clause).</li>
 *   <li>The registration gate is domain-scoped: it delegates to the domain-filtered
 *       {@code exists} finder, so an invite stamped with brand X does not admit a
 *       registration on brand Y.</li>
 * </ul>
 * Repositories are Mockito mocks — no database required.
 */
class AccountStoreDomainScopeTest {

    private final AllowlistRepository allowlist = mock(AllowlistRepository.class);
    private final AccountRowRepository accounts = mock(AccountRowRepository.class);
    private final BffSessionRepository sessions = mock(BffSessionRepository.class);
    private final NamespaceGrantRepository grants = mock(NamespaceGrantRepository.class);

    private AccountStore store() {
        return new AccountStore(allowlist, accounts, sessions, grants, "");
    }

    // ── Allowlist — reads ─────────────────────────────────────────────

    @Test
    void allowedEmails_domainScoped_callsDomainFilteredFinder() {
        Allowlist row = new Allowlist("google", "alice@brand.com", "brandx", LocalDateTime.now());
        when(allowlist.findByProviderAndDomainOrderByHandle("google", "brandx"))
                .thenReturn(Flux.just(row));

        StepVerifier.create(store().allowedEmails("brandx"))
                .expectNext("alice@brand.com")
                .verifyComplete();

        verify(allowlist).findByProviderAndDomainOrderByHandle("google", "brandx");
        verify(allowlist, never()).findByProviderOrderByHandle("google");
    }

    @Test
    void allowedEmails_unscoped_callsUnscopedFinder() {
        Allowlist xRow = new Allowlist("google", "x@brand.com", "brandx", LocalDateTime.now());
        Allowlist yRow = new Allowlist("google", "y@brand.com", "brandy", LocalDateTime.now());
        when(allowlist.findByProviderOrderByHandle("google")).thenReturn(Flux.just(xRow, yRow));

        StepVerifier.create(store().allowedEmails())
                .expectNext("x@brand.com", "y@brand.com")
                .verifyComplete();

        verify(allowlist).findByProviderOrderByHandle("google");
        verify(allowlist, never()).findByProviderAndDomainOrderByHandle("google", "brandx");
    }

    @Test
    void allowedDiscord_domainScoped_callsDomainFilteredFinder() {
        Allowlist row = new Allowlist("discord", "alice#1234", "brandx", LocalDateTime.now());
        when(allowlist.findByProviderAndDomainOrderByHandle("discord", "brandx"))
                .thenReturn(Flux.just(row));

        StepVerifier.create(store().allowedDiscord("brandx"))
                .expectNext("alice#1234")
                .verifyComplete();

        verify(allowlist).findByProviderAndDomainOrderByHandle("discord", "brandx");
    }

    // ── Allowlist — registration gate ─────────────────────────────────

    @Test
    void isEmailInvited_domainScoped_callsDomainFilteredExists() {
        when(allowlist.existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandx"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store().isEmailInvited("alice@brand.com", "brandx"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandx");
        verify(allowlist, never()).existsByProviderAndHandle("google", "alice@brand.com");
    }

    @Test
    void isEmailInvited_domainScoped_lowercasesHandle() {
        when(allowlist.existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandx"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store().isEmailInvited("ALICE@BRAND.COM", "brandx"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandx");
    }

    /** The gap this scoping closes: brand-X's invite must not admit a brand-Y registration. */
    @Test
    void isEmailInvited_domainScoped_deniesInviteFromAnotherBrand() {
        // alice is invited to brandx only — the brandy gate must see no row.
        when(allowlist.existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandy"))
                .thenReturn(Mono.just(false));

        StepVerifier.create(store().isEmailInvited("alice@brand.com", "brandy"))
                .expectNext(false)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandy");
    }

    @Test
    void isDiscordInvited_domainScoped_callsDomainFilteredExists() {
        when(allowlist.existsByProviderAndHandleAndDomain("discord", "alice#1234", "brandy"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store().isDiscordInvited("alice#1234", "brandy"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("discord", "alice#1234", "brandy");
        verify(allowlist, never()).existsByProviderAndHandle("discord", "alice#1234");
    }

    /** Back-compat: the deprecated unscoped overloads still hit the unscoped finder. */
    @Test
    @SuppressWarnings("deprecation")
    void isEmailInvited_unscoped_stillCallsUnscopedExists() {
        when(allowlist.existsByProviderAndHandle("google", "alice@brand.com"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store().isEmailInvited("alice@brand.com"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandle("google", "alice@brand.com");
    }

    // ── Allowlist — writes ────────────────────────────────────────────

    @Test
    void inviteEmail_stampsCallerDomain() {
        when(allowlist.insertIfAbsent("google", "bob@brand.com", "brandx")).thenReturn(Mono.just(1L));

        StepVerifier.create(store().inviteEmail("bob@brand.com", "brandx"))
                .verifyComplete();

        verify(allowlist).insertIfAbsent("google", "bob@brand.com", "brandx");
    }

    @Test
    void inviteEmail_lowercasesHandle() {
        when(allowlist.insertIfAbsent("google", "bob@brand.com", "brandx")).thenReturn(Mono.just(1L));

        StepVerifier.create(store().inviteEmail("BOB@BRAND.COM", "brandx"))
                .verifyComplete();

        verify(allowlist).insertIfAbsent("google", "bob@brand.com", "brandx");
    }

    @Test
    void inviteDiscord_stampsCallerDomain() {
        when(allowlist.insertIfAbsent("discord", "alice#1234", "brandy")).thenReturn(Mono.just(1L));

        StepVerifier.create(store().inviteDiscord("alice#1234", "brandy"))
                .verifyComplete();

        verify(allowlist).insertIfAbsent("discord", "alice#1234", "brandy");
    }

    // ── Allowlist — deletes ───────────────────────────────────────────

    @Test
    void revokeEmail_includesDomainPredicate() {
        when(allowlist.deleteByProviderAndHandleAndDomain("google", "bob@brand.com", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store().revokeEmail("bob@brand.com", "brandx"))
                .verifyComplete();

        verify(allowlist).deleteByProviderAndHandleAndDomain("google", "bob@brand.com", "brandx");
    }

    @Test
    void revokeDiscord_includesDomainPredicate() {
        when(allowlist.deleteByProviderAndHandleAndDomain("discord", "alice#1234", "brandy"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store().revokeDiscord("alice#1234", "brandy"))
                .verifyComplete();

        verify(allowlist).deleteByProviderAndHandleAndDomain("discord", "alice#1234", "brandy");
    }

    // ── NamespaceGrant — reads ────────────────────────────────────────

    @Test
    void allGrants_domainScoped_callsDomainFilteredFinder() {
        NamespaceGrant row = new NamespaceGrant("alice", "hugmesh-pki", "brandx", LocalDateTime.now());
        when(grants.findByDomainOrderByGranteeAscNamespaceAsc("brandx"))
                .thenReturn(Flux.just(row));

        StepVerifier.create(store().allGrants("brandx"))
                .assertNext(list -> {
                    assert list.size() == 1;
                    assert list.get(0).get("user").equals("alice");
                    assert ((List<?>) list.get(0).get("namespaces")).contains("hugmesh-pki");
                })
                .verifyComplete();

        verify(grants).findByDomainOrderByGranteeAscNamespaceAsc("brandx");
        verify(grants, never()).findAllByOrderByGranteeAscNamespaceAsc();
    }

    @Test
    void allGrants_unscoped_callsUnscopedFinder() {
        NamespaceGrant xRow = new NamespaceGrant("alice", "hugmesh-pki", "brandx", LocalDateTime.now());
        NamespaceGrant yRow = new NamespaceGrant("bob", "hugmesh-backend", "brandy", LocalDateTime.now());
        when(grants.findAllByOrderByGranteeAscNamespaceAsc()).thenReturn(Flux.just(xRow, yRow));

        StepVerifier.create(store().allGrants())
                .assertNext(list -> { assert list.size() == 2; })
                .verifyComplete();

        verify(grants).findAllByOrderByGranteeAscNamespaceAsc();
        verify(grants, never()).findByDomainOrderByGranteeAscNamespaceAsc("brandx");
    }

    // ── NamespaceGrant — writes / deletes ─────────────────────────────

    @Test
    void grant_stampsCallerDomain() {
        when(grants.insertIfAbsent("alice", "hugmesh-pki", "brandx")).thenReturn(Mono.just(1L));

        StepVerifier.create(store().grant("alice", "hugmesh-pki", "brandx"))
                .verifyComplete();

        verify(grants).insertIfAbsent("alice", "hugmesh-pki", "brandx");
    }

    @Test
    void revoke_includesDomainPredicate() {
        when(grants.deleteByGranteeAndNamespaceAndDomain("alice", "hugmesh-pki", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store().revoke("alice", "hugmesh-pki", "brandx"))
                .verifyComplete();

        verify(grants).deleteByGranteeAndNamespaceAndDomain("alice", "hugmesh-pki", "brandx");
    }
}

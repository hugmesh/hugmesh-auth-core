package net.hugmesh.authcore.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.mock;

/**
 * The registration gate END TO END through the {@link AccountStore} facade, over the REAL
 * (changeset 003 + 220) {@code allowlist} table — hugmesh-auth-core issue #1.
 *
 * <p>This closes the seam between the two test classes that already existed either side of it:
 * {@link AccountStoreDomainScopeTest} proves the facade DELEGATES to the domain-filtered
 * repository method but does so against Mockito mocks (it would keep passing if the derived
 * finder itself were wrong), and {@link AllowlistRepositoryTest} proves the finder emits a
 * {@code domain} predicate but never goes through the facade (it would keep passing if
 * {@code AccountStore} called the unscoped one). Neither, alone, fails when the GATE — the
 * pair of them — is unscoped. This one does: seeded through the production
 * {@code AccountStore.inviteEmail} / {@code inviteDiscord} writes and asserted through the
 * production {@code isEmailInvited} / {@code isDiscordInvited} reads, so reverting the facade
 * to {@code existsByProviderAndHandle} turns every {@code expectNext(false)} below into
 * {@code true}.
 *
 * <p>Only the allowlist repository is real; the account/session/grant repositories are mocks
 * because no path under test touches them (and {@code seedAdmins} never runs — the store is
 * constructed directly, with an empty admin-email list).
 */
@DataR2dbcTest
@Import({AllowlistTestDatabaseConfig.class})
class AccountStoreAllowlistGateTest {

    private static final String BRAND_A = "brand-a";
    private static final String BRAND_B = "brand-b";

    @Autowired AllowlistRepository allowlist;

    private AccountStore store() {
        return new AccountStore(allowlist,
                mock(AccountRowRepository.class),
                mock(BffSessionRepository.class),
                mock(NamespaceGrantRepository.class),
                "");
    }

    /** An entry for domain A does NOT admit the same identifier on domain B. */
    @Test
    void emailInvitedOnBrandA_isNotInvitedOnBrandB() {
        AccountStore store = store();
        store.inviteEmail("alice@example.test", BRAND_A).block();

        StepVerifier.create(store.isEmailInvited("alice@example.test", BRAND_B))
                .expectNext(false).verifyComplete();
    }

    /** The intended domain still works — the same row the assertion above refuses for B. */
    @Test
    void emailInvitedOnBrandA_isInvitedOnBrandA() {
        AccountStore store = store();
        store.inviteEmail("alice@example.test", BRAND_A).block();

        StepVerifier.create(store.isEmailInvited("alice@example.test", BRAND_A))
                .expectNext(true).verifyComplete();
    }

    @Test
    void discordInvitedOnBrandA_isNotInvitedOnBrandB_butIsOnBrandA() {
        AccountStore store = store();
        store.inviteDiscord("alice#1234", BRAND_A).block();

        StepVerifier.create(store.isDiscordInvited("alice#1234", BRAND_A))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isDiscordInvited("alice#1234", BRAND_B))
                .expectNext(false).verifyComplete();
    }

    /**
     * The write path folds case ({@code invite}) and so does the read path ({@code isInvited}),
     * so a differently-cased registration is admitted on its OWN brand only — a fold that
     * ignored the domain would be a second way to cross brands.
     */
    @Test
    void caseFoldingDoesNotLeakAcrossBrands() {
        AccountStore store = store();
        store.inviteEmail("MixedCase@Example.Test", BRAND_A).block();

        StepVerifier.create(store.isEmailInvited("mixedcase@example.test", BRAND_A))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isEmailInvited("MIXEDCASE@EXAMPLE.TEST", BRAND_B))
                .expectNext(false).verifyComplete();
    }

    /**
     * The single-tenant install the fix must not change: rows stamped with the
     * {@link AccountStore#DEFAULT_DOMAIN} the admin seed and the changeset-220 back-fill use
     * still admit, and are still not visible to a branded deployment.
     */
    @Test
    void defaultDomainRowsStillAdmitOnTheDefaultDomain() {
        AccountStore store = store();
        store.inviteEmail("legacy@example.test", AccountStore.DEFAULT_DOMAIN).block();

        StepVerifier.create(store.isEmailInvited("legacy@example.test", AccountStore.DEFAULT_DOMAIN))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isEmailInvited("legacy@example.test", BRAND_A))
                .expectNext(false).verifyComplete();
    }

    /** Two brands may each hold their own row for one identifier; each answers for itself. */
    @Test
    void perBrandRowsAreIndependentThroughTheFacade() {
        AccountStore store = store();
        store.inviteEmail("both@example.test", BRAND_A).block();
        store.inviteEmail("both@example.test", BRAND_B).block();

        StepVerifier.create(store.isEmailInvited("both@example.test", BRAND_A))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isEmailInvited("both@example.test", BRAND_B))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isEmailInvited("both@example.test", "brand-c"))
                .expectNext(false).verifyComplete();
    }

    /** A revoke on one brand leaves the other brand's invite intact (domain in the DELETE). */
    @Test
    void revokeOnOneBrandDoesNotDisarmTheOther() {
        AccountStore store = store();
        store.inviteEmail("shared@example.test", BRAND_A).block();
        store.inviteEmail("shared@example.test", BRAND_B).block();

        store.revokeEmail("shared@example.test", BRAND_A).block();

        StepVerifier.create(store.isEmailInvited("shared@example.test", BRAND_A))
                .expectNext(false).verifyComplete();
        StepVerifier.create(store.isEmailInvited("shared@example.test", BRAND_B))
                .expectNext(true).verifyComplete();
    }
}

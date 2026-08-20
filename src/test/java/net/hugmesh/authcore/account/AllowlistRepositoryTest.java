package net.hugmesh.authcore.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;

/**
 * R2DBC-H2 data slice for the {@code allowlist} registration-gate finders. The Mockito
 * tests in {@link AccountStoreDomainScopeTest} prove the facade DELEGATES to the right
 * repository method; this slice proves the DERIVED finders actually resolve and emit the
 * intended SQL against the real (changeset 003 + 220) table — in particular that
 * {@code existsByProviderAndHandleAndDomain} puts {@code domain} in the WHERE clause, so a
 * handle invited to one brand does not satisfy another brand's gate.
 */
@DataR2dbcTest
@Import({AllowlistTestDatabaseConfig.class})
class AllowlistRepositoryTest {

    @Autowired AllowlistRepository repo;

    /** Seed via the production insert-if-absent so the row is stamped exactly as prod does. */
    private void invite(String provider, String handle, String domain) {
        repo.insertIfAbsent(provider, handle, domain).block();
    }

    @Test
    void existsScoped_trueOnlyInTheInvitedDomain() {
        invite("google", "alice@brand.com", "brandx");

        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandx"))
                .expectNext(true).verifyComplete();
        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "alice@brand.com", "brandy"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void existsScoped_isProviderScopedToo() {
        invite("google", "alice@brand.com", "brandx");

        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("discord", "alice@brand.com", "brandx"))
                .expectNext(false).verifyComplete();
    }

    @Test
    void existsScoped_unknownHandle_isFalse() {
        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "nobody@brand.com", "brandx"))
                .expectNext(false).verifyComplete();
    }

    /** The gap: the unscoped finder is true for a brand the handle was never invited to. */
    @Test
    void existsUnscoped_isCrossBrandPermissive_whereTheScopedOneIsNot() {
        invite("discord", "alice#1234", "brandx");

        StepVerifier.create(repo.existsByProviderAndHandle("discord", "alice#1234"))
                .expectNext(true).verifyComplete();
        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("discord", "alice#1234", "brandy"))
                .expectNext(false).verifyComplete();
    }

    /** Same handle invited to two brands: each brand's gate sees its OWN row (widened PK). */
    @Test
    void existsScoped_perBrandRowsAreIndependent() {
        invite("google", "bob@brand.com", "brandx");
        invite("google", "bob@brand.com", "brandy");

        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "bob@brand.com", "brandx"))
                .expectNext(true).verifyComplete();
        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "bob@brand.com", "brandy"))
                .expectNext(true).verifyComplete();
        StepVerifier.create(repo.existsByProviderAndHandleAndDomain("google", "bob@brand.com", "brandz"))
                .expectNext(false).verifyComplete();
    }
}

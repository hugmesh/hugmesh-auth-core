package net.hugmesh.authcore.account;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression cover for the allowlist / admin-seed / namespace-grant handle folds in
 * {@link AccountStore}: every one of them must fold with {@link Locale#ROOT}, exactly like
 * {@link AccountStore#idFor(String, String)} already does (see {@link AccountStoreIdForTest}).
 *
 * <p>Before this cover landed the allowlist paths used the bare, default-locale
 * {@code String#toLowerCase()}. Under a Turkish/Azeri default locale that maps {@code 'I'}
 * to the dotless {@code 'ı'}, so an identifier containing an upper-case {@code I} folded to
 * a DIFFERENT string on a {@code LANG=tr_TR.UTF-8} JVM than anywhere else. Write and read
 * fold independently, so an invite written on one container and read on another produced
 * a handle mismatch and a legitimately invited identifier was refused at the registration
 * gate — fail-closed, but a real correctness gap, and the same class of bug {@code idFor}
 * was fixed for.
 *
 * <p>Every test here pins the default locale to {@code tr-TR} itself and asserts the trap is
 * live in this JVM before exercising the store, so the cover cannot pass vacuously on a host
 * whose locale happens to be benign. The default is restored in {@link AfterEach} so the
 * change cannot leak into other classes sharing the same surefire fork.
 */
class AccountStoreAllowlistLocaleTest {

    private static final Locale TURKISH = Locale.forLanguageTag("tr-TR");

    private final Locale originalDefault = Locale.getDefault();

    private final AllowlistRepository allowlist = mock(AllowlistRepository.class);
    private final AccountRowRepository accounts = mock(AccountRowRepository.class);
    private final BffSessionRepository sessions = mock(BffSessionRepository.class);
    private final NamespaceGrantRepository grants = mock(NamespaceGrantRepository.class);

    @BeforeEach
    void pinTurkishDefaultLocale() {
        Locale.setDefault(TURKISH);
        // Guard against a vacuous pass: the default-locale fold MUST produce the dotless 'ı'
        // here, otherwise none of the assertions below distinguish Locale.ROOT from default.
        assertThat("I".toLowerCase()).isEqualTo("ı");
    }

    @AfterEach
    void restoreLocale() {
        Locale.setDefault(originalDefault);
    }

    private AccountStore store(String adminEmails) {
        return new AccountStore(allowlist, accounts, sessions, grants, adminEmails);
    }

    // ── Registration gate reads (domain-scoped) ───────────────────────

    @Test
    void isEmailInvited_domainScoped_foldsWithLocaleRoot() {
        when(allowlist.existsByProviderAndHandleAndDomain("google", "istanbul@example.test", "brandx"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store("").isEmailInvited("ISTANBUL@EXAMPLE.TEST", "brandx"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("google", "istanbul@example.test", "brandx");
    }

    @Test
    void isDiscordInvited_domainScoped_foldsWithLocaleRoot() {
        when(allowlist.existsByProviderAndHandleAndDomain("discord", "iris#0001", "brandx"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store("").isDiscordInvited("IRIS#0001", "brandx"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandleAndDomain("discord", "iris#0001", "brandx");
    }

    // ── Registration gate reads (deprecated unscoped overloads) ───────

    @Test
    @SuppressWarnings("deprecation")
    void isEmailInvited_unscoped_foldsWithLocaleRoot() {
        when(allowlist.existsByProviderAndHandle("google", "istanbul@example.test"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store("").isEmailInvited("ISTANBUL@EXAMPLE.TEST"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandle("google", "istanbul@example.test");
    }

    @Test
    @SuppressWarnings("deprecation")
    void isDiscordInvited_unscoped_foldsWithLocaleRoot() {
        when(allowlist.existsByProviderAndHandle("discord", "iris#0001"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(store("").isDiscordInvited("IRIS#0001"))
                .expectNext(true)
                .verifyComplete();

        verify(allowlist).existsByProviderAndHandle("discord", "iris#0001");
    }

    // ── Allowlist writes: invite + revoke must key the row the way the reads look it up ──

    @Test
    void inviteEmail_foldsWithLocaleRoot() {
        when(allowlist.insertIfAbsent("google", "istanbul@example.test", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").inviteEmail("ISTANBUL@EXAMPLE.TEST", "brandx"))
                .verifyComplete();

        verify(allowlist).insertIfAbsent("google", "istanbul@example.test", "brandx");
    }

    @Test
    void inviteDiscord_foldsWithLocaleRoot() {
        when(allowlist.insertIfAbsent("discord", "iris#0001", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").inviteDiscord("IRIS#0001", "brandx"))
                .verifyComplete();

        verify(allowlist).insertIfAbsent("discord", "iris#0001", "brandx");
    }

    @Test
    void revokeEmail_foldsWithLocaleRoot() {
        when(allowlist.deleteByProviderAndHandleAndDomain("google", "istanbul@example.test", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").revokeEmail("ISTANBUL@EXAMPLE.TEST", "brandx"))
                .verifyComplete();

        verify(allowlist).deleteByProviderAndHandleAndDomain("google", "istanbul@example.test", "brandx");
    }

    @Test
    void revokeDiscord_foldsWithLocaleRoot() {
        when(allowlist.deleteByProviderAndHandleAndDomain("discord", "iris#0001", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").revokeDiscord("IRIS#0001", "brandx"))
                .verifyComplete();

        verify(allowlist).deleteByProviderAndHandleAndDomain("discord", "iris#0001", "brandx");
    }

    // ── Admin-email seed: the configured set must fold the way ensureAccount folds
    //    the handle it compares against, or a configured admin is minted as a plain user. ──

    @Test
    void adminEmails_foldWithLocaleRoot_soEnsureAccountRecognisesTheAdmin() {
        when(accounts.findById("google:istanbul@example.test")).thenReturn(Mono.empty());
        when(accounts.save(org.mockito.ArgumentMatchers.any()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account a = store("ISTANBUL@EXAMPLE.TEST").ensureAccount("google", "istanbul@example.test").block();

        assertThat(a).isNotNull();
        assertThat(a.roles()).contains("admin");
    }

    // ── Namespace grants: the grantee key must match the Locale.ROOT-folded account id ──

    @Test
    void grant_foldsGranteeWithLocaleRoot() {
        when(grants.insertIfAbsent("google:istanbul@example.test", "games", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").grant("google:ISTANBUL@EXAMPLE.TEST", "games", "brandx"))
                .verifyComplete();

        verify(grants).insertIfAbsent("google:istanbul@example.test", "games", "brandx");
    }

    @Test
    void revoke_foldsGranteeWithLocaleRoot() {
        when(grants.deleteByGranteeAndNamespaceAndDomain("google:istanbul@example.test", "games", "brandx"))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(store("").revoke("google:ISTANBUL@EXAMPLE.TEST", "games", "brandx"))
                .verifyComplete();

        verify(grants).deleteByGranteeAndNamespaceAndDomain("google:istanbul@example.test", "games", "brandx");
    }
}

package systems.snapdragon.authcore.account;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression cover for {@link AccountStore#idFor(String, String)}: the WRITE-side handle
 * fold must trim whitespace and use {@link Locale#ROOT} (not the JVM default locale) —
 * exactly like the equivalent READ-side fold in gateway's
 * {@code GatewayRouteAccessFilter#addNativeAccountIdForms}
 * ({@code candidate.trim().toLowerCase(Locale.ROOT)}). Divergence here fails INERT (a
 * mismatch just means a deny-dodge check silently doesn't match, never a false ALLOW) but
 * is a real correctness gap: under a Turkish/Azeri default locale, {@code "I".toLowerCase()}
 * yields a dotless {@code 'ı'} instead of {@code 'i'}, and a plain {@code .toLowerCase()}
 * (no trim) leaves stray leading/trailing whitespace embedded in the stored key.
 */
class AccountStoreIdForTest {

    private final Locale originalDefault = Locale.getDefault();

    @AfterEach
    void restoreLocale() {
        Locale.setDefault(originalDefault);
    }

    @Test
    void idFor_trimsWhitespace() {
        assertThat(AccountStore.idFor("google", "  Alice@Example.com  "))
                .isEqualTo("google:alice@example.com");
    }

    @Test
    void idFor_nullHandle_doesNotThrow() {
        assertThat(AccountStore.idFor("google", null)).isEqualTo("google:");
    }

    @Test
    void idFor_isLocaleIndependent_underTurkishDefaultLocale() {
        // The classic "Turkish I" trap: under a tr-TR default locale, String#toLowerCase()
        // (no-arg) maps 'I' to the dotless 'ı', not 'i'. idFor must fold via Locale.ROOT so
        // the same handle always produces the same account id, regardless of the JVM's
        // default locale.
        Locale.setDefault(new Locale("tr", "TR"));
        try {
            assertThat(AccountStore.idFor("casdoor", "Istanbul"))
                    .isEqualTo("casdoor:istanbul");
        } finally {
            Locale.setDefault(originalDefault);
        }
    }

    // ── Behavioral: the fold used to key/lookup a row must match the fold used to
    //    build the row's stored `handle` column exactly, so a whitespace-padded or
    //    non-ASCII-cased handle round-trips through ensureAccount to the SAME id an
    //    already-normalized re-login would resolve. ──────────────────────────────

    private final AllowlistRepository allowlist = mock(AllowlistRepository.class);
    private final AccountRowRepository accounts = mock(AccountRowRepository.class);
    private final BffSessionRepository sessions = mock(BffSessionRepository.class);
    private final NamespaceGrantRepository grants = mock(NamespaceGrantRepository.class);

    private AccountStore store() {
        return new AccountStore(allowlist, accounts, sessions, grants, "admin@snapdragon.systems");
    }

    @Test
    void ensureAccount_twoArg_whitespacePaddedHandle_resolvesToTrimmedId() {
        when(accounts.findById("google:bob@example.com")).thenReturn(Mono.empty());
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account a = store().ensureAccount("google", "  Bob@Example.com  ").block();

        assertThat(a.id()).isEqualTo("google:bob@example.com");

        // The row saved under the trimmed id must ALSO carry the trimmed handle — not a
        // whitespace-padded one — so the id and the stored handle column never diverge.
        ArgumentCaptor<AccountRow> captor = ArgumentCaptor.forClass(AccountRow.class);
        verify(accounts).save(captor.capture());
        assertThat(captor.getValue().id()).isEqualTo("google:bob@example.com");
        assertThat(captor.getValue().handle()).isEqualTo("bob@example.com");
    }

    @Test
    void ensureAccount_threeArg_existingAccount_alreadyNormalizedHandle_keyIsUnchanged() {
        // An existing account keyed on an already-lowered, already-trimmed value must NOT
        // change key on a re-login now that idFor also trims + folds via Locale.ROOT — the
        // fold is idempotent for already-normalized input.
        AccountRow existing = new AccountRow(
                "casdoor:carol", "casdoor", "carol", true, "user", LocalDateTime.now().minusDays(1));
        when(accounts.findById("casdoor:carol")).thenReturn(Mono.just(existing));
        when(accounts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Account resynced = store().ensureAccount("casdoor", "carol", List.of("user", "mod")).block();

        assertThat(resynced.id()).isEqualTo("casdoor:carol");
        assertThat(resynced.roles()).containsExactlyInAnyOrder("user", "mod");
    }
}

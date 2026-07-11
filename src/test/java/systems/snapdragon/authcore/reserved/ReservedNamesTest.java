package systems.snapdragon.authcore.reserved;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the canonical reserved-username list, the normaliser, and
 * the route-prefix helpers. The username list + normaliser expectations mirror
 * snapdragon-actions' {@code ReservedNamesTest} (the two RESERVED blocks are
 * byte-for-byte identical); the {@code firstSegment}/{@code isReservedPrefix}
 * cases are admin-bff-only.
 */
class ReservedNamesTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "admin", "apidocs", "be", "bff", "fragments", "login", "logout",
            "mod", "user", "users", "api", "matrix", "mastodon", "pleroma", "forum",
            "oauth", "oauth2", "id", "auth", "scale", "headscale", "www", "root",
            "static", "assets", "public", "health", "healthz", "actuator",
            "metrics", "well-known", "favicon", "robots", "sitemap", "status",
            "support", "help", "social", "gm", "pki", "vault", "argocd",
            "gitlab", "registry", "games", "play",
            // The 14 games-app labels backported to reach the canonical 61
            // (parity with snapdragon-federation-api / snapdragon-user-bff-api).
            "api-docs", "banned", "docs", "games-dodecahedron", "games-rpg-maker",
            "games-three-wizards", "games-vn-maker", "producer",
            "producer-registration", "publisher", "registration", "_remotes",
            "wasm", "wasm-fragment"})
    void everyCanonicalLabelIsReserved(String label) {
        // NOTE (consolidation): '@system' (Notifications PR3) is NOT a canonical
        // cross-repo label — it is reserved via the SEPARATE RESERVED_PLATFORM_INTERNAL
        // set, exercised by systemIsReservedPlatformInternal_* below — so it is
        // deliberately absent from this canonical list.
        assertThat(ReservedNames.isReserved(label)).isTrue();
    }

    @Test
    void reservedSetIsExactlyTheCanonical77Labels() {
        // Guards against silent drift from the canonical reserved-prefixes.yaml
        // (and the RESERVED[_LABELS] copies in snapdragon-federation-api /
        // snapdragon-actions): the count must stay 77 (the union of gateway
        // prefixes, reserved subdomains, the snapdragon.games app prefixes, and the
        // defensive web/infra names — incl. the federated 'forum'/'phpbb' forum
        // labels). The neutral '@system' notification sender (Notifications PR3) is
        // reserved SEPARATELY via RESERVED_PLATFORM_INTERNAL, so it does NOT change
        // this cross-repo canonical-sync count.
        // 62 -> 64: added `tube` (LocalTube /tube/content/** route) +
        // `games-instances-console` (per-instance game-server console dispatcher
        // Service the /games/servers/** route targets).
        // 64 -> 70: reconciled with the canonical YAML — added `superadmin`,
        // `_synapse`, `media`, `phpbb`, `owncast`, `wiki` (canonical revision 3).
        // 70 -> 77: reconciled with canonical revisions 4-6 — added
        // `character-studio`, `v1` (revision 4), `index.html`, `favicon.ico`,
        // `importmap.json`, `remoteentry.json` (revision 5 fe webroot filenames),
        // and `ai` (revision 6 edge-AI host).
        assertThat(ReservedNames.RESERVED).hasSize(77);
    }

    @ParameterizedTest
    @ValueSource(strings = {"tube", "games-instances-console"})
    void optionalServicePrefixesAreReserved(String label) {
        // `tube` (LocalTube /tube/content/** route) and `games-instances-console`
        // (the per-instance game-server console dispatcher Service targeted by the
        // /games/servers/** route) are reserved for parity with the canonical
        // source — a user must not be able to register either handle.
        assertThat(ReservedNames.isReserved(label)).isTrue();
        assertThat(ReservedNames.RESERVED).contains(label);
    }

    @ParameterizedTest
    @ValueSource(strings = {"superadmin", "_synapse", "media", "phpbb", "owncast", "wiki"})
    void reconciledCanonicalLabelsAreReserved(String label) {
        // The 6 labels added to reconcile this copy with the canonical
        // reserved-prefixes.yaml (drift fix): `superadmin` (the TAILNET superadmin
        // App-Store console /superadmin/appstore/** route), `_synapse` + `media`
        // (the publicly-routable homeserver client surfaces /_synapse/** + /media/**),
        // `phpbb` (the phpBB forum forward-reserve), and `owncast` + `wiki` (the
        // optional video/wiki services, forward-reserved like forum/phpbb).
        assertThat(ReservedNames.isReserved(label)).isTrue();
        assertThat(ReservedNames.RESERVED).contains(label);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "character-studio", "v1", "index.html", "favicon.ico",
            "importmap.json", "remoteentry.json", "ai"})
    void everyCanonicalRevision4To6LabelIsReserved(String label) {
        // The 7 labels added to reconcile this copy with canonical revisions 4-6 of
        // reserved-prefixes.yaml: `character-studio` (the Character Studio VN
        // micro-frontend /character-studio/** fe-gateway route) + `v1` (the edge-AI
        // /v1/analyze/** be-gateway route) — revision 4; `index.html`, `favicon.ico`,
        // `importmap.json`, `remoteentry.json` (the fe-gateway anonymous-SPA-shell
        // webroot filenames) — revision 5; and `ai` (the edge-AI inference-tier host
        // ai.snapdragon.systems) — revision 6. Stored lower-case like every other
        // entry (the on-disk manifest filename is "remoteEntry.json" — matching is
        // case-insensitive; isReserved() lower-cases the candidate first).
        assertThat(ReservedNames.isReserved(label)).isTrue();
        assertThat(ReservedNames.RESERVED).contains(label);
    }

    @Test
    void systemLabelIsReserved() {
        // The neutral @system notification sender (Notifications PR3) — reserved
        // so a regular user can NEVER register 'system' and spoof the faceless
        // infra account every platform notification comes from. It is reserved via
        // the platform-internal set (asserted in
        // systemIsReservedPlatformInternal_*), NOT the canonical RESERVED block.
        assertThat(ReservedNames.isReserved("system")).isTrue();
        assertThat(ReservedNames.isReserved("SYSTEM")).isTrue();
        assertThat(ReservedNames.isReserved("  System  ")).isTrue();
        assertThat(ReservedNames.RESERVED_PLATFORM_INTERNAL).contains("system");
    }

    @Test
    void forumLabelIsReserved() {
        // The phpBB forum surface (/social/forum, /bff/forum, /bff/admin/forum) —
        // reserved defensively so a vanity username 'forum' can never collide with
        // a future forum. subdomain / forum/ first-segment path.
        assertThat(ReservedNames.isReserved("forum")).isTrue();
        assertThat(ReservedNames.isReserved("FORUM")).isTrue();
        assertThat(ReservedNames.RESERVED).contains("forum");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ADMIN", "Admin", "  Login  ", "GAMES", "Api",
            // remoteEntry.json is the actual mixed-case on-disk manifest filename;
            // stored lower-case in the set, the case-insensitive raw-form compare in
            // isReserved() still catches the mixed-case candidate.
            "remoteEntry.json", "RemoteEntry.JSON"})
    void reservedCheckIsCaseInsensitiveAndTrimmed(String label) {
        assertThat(ReservedNames.isReserved(label)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"system", "System", "SYSTEM", "  system  "})
    void systemIsReservedPlatformInternal_soNoHumanCanClaimTheNeutralSender(String label) {
        // The per-domain neutral @system notifications sender (Notifications PR3): the
        // name must be unclaimable by any human registration so it can't be impersonated.
        assertThat(ReservedNames.isReserved(label)).isTrue();
        assertThat(ReservedNames.RESERVED_PLATFORM_INTERNAL).contains("system");
    }

    @Test
    void systemLivesInTheSeparatePlatformInternalSet_notTheCanonicalCrossRepoSet() {
        // 'system' is reserved via the SEPARATE platform-internal set, NOT the canonical
        // RESERVED block — so it does NOT change the cross-repo size-77 contract below and
        // requires no byte-for-byte edit to the sibling ReservedNames copies.
        assertThat(ReservedNames.RESERVED).doesNotContain("system");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "_matrix", "_fragments", "well.known", "well known", "ad-min", "a.d.m.i.n"})
    void underscoreAndSeparatorVariantsNormaliseOntoReservedLabels(String label) {
        assertThat(ReservedNames.isReserved(label)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "magus", "alice", "bob42", "game-master", "admin-helper",
            "apiary", "username", "logan", "playful", "matrixx", "ider"})
    void ordinaryUsernamesAreNotReserved(String label) {
        assertThat(ReservedNames.isReserved(label)).isFalse();
    }

    @Test
    void nullAndBlankAreNotReserved() {
        assertThat(ReservedNames.isReserved(null)).isFalse();
        assertThat(ReservedNames.isReserved("")).isFalse();
        assertThat(ReservedNames.isReserved("   ")).isFalse();
    }

    @Test
    void normalizeFoldsToDnsLabelForm() {
        assertThat(ReservedNames.normalize("  Admin  ")).isEqualTo("admin");
        assertThat(ReservedNames.normalize("_matrix")).isEqualTo("matrix");
        assertThat(ReservedNames.normalize("well.known")).isEqualTo("well-known");
        assertThat(ReservedNames.normalize("Game_Master")).isEqualTo("game-master");
    }

    // ── Route-prefix helpers (admin-bff-only) ──────────────────────────────

    @ParameterizedTest
    @CsvSource({
            "/api/admin/**, api",
            "/_matrix/**,   matrix",
            "/bff/login,    bff",
            "/admin/**,     admin",
            "/login/**,     login",
            "/social/matrix/**, social",
            "/api/games/,   api",
    })
    void firstSegment_extractsNormalisedLeadingSegment(String path, String expected) {
        assertThat(ReservedNames.firstSegment(path)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/**", "**", "/*"})
    void firstSegment_isEmptyForRootOrBareWildcard(String path) {
        assertThat(ReservedNames.firstSegment(path)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/**", "/admin/x", "/_matrix/**", "/games/lobby"})
    void isReservedPrefix_trueForDedicatedPrefixes(String path) {
        assertThat(ReservedNames.isReservedPrefix(path)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/widgets/**", "/myteam/x", "/", "/**"})
    void isReservedPrefix_falseForNewOrEmptyPrefixes(String path) {
        assertThat(ReservedNames.isReservedPrefix(path)).isFalse();
    }
}

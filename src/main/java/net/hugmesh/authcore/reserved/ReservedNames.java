package net.hugmesh.authcore.reserved;

import java.text.Normalizer;
import java.util.Set;

/**
 * The platform-wide RESERVED USERNAME / PREFIX list and the username
 * normaliser used to enforce it.
 *
 * <p>A username must never equal a label that is also a dedicated app
 * path/prefix route or a reserved subdomain, otherwise the freshly
 * created user's vanity surface (e.g. {@code <user>.hugmesh.net}
 * or {@code /user/<user>}) would shadow — or be shadowed by — a gateway
 * route. We reject such usernames at the FIRST point the platform sees
 * them (registration) and again at this admin/provision layer.
 *
 * <p><b>CANONICAL SOURCE.</b> This list is the union of, and MUST stay in
 * lockstep with, the gateway route prefixes defined in
 * {@code hugmesh-gateway} —
 * {@code src/main/java/net/hugmesh/gateway/cache/CanonicalSeed.java}
 * (mirrored in {@code cluster/manifests/route-access/schema.sql} and
 * {@code hugmesh-gateway/compose/route-access-seed.sql}). Concretely it
 * is the union of:
 *
 * <ul>
 *   <li>fe-gateway route prefixes: admin, apidocs, be, bff, _fragments,
 *       fragments, login, mod, user;</li>
 *   <li>be-gateway route prefixes: api, _matrix, oauth;</li>
 *   <li>reserved subdomains: id, api, matrix, mastodon, scale, headscale,
 *       www;</li>
 *   <li>the hugmesh.games app prefixes: games, play;</li>
 *   <li>defensive web/infra names (root, static, assets, public, health,
 *       healthz, actuator, metrics, well-known, favicon, robots, sitemap,
 *       status, support, help, social, gm, pki, vault, argocd, gitlab,
 *       registry, logout, users, auth).</li>
 * </ul>
 *
 * <p>The SAME canonical list is duplicated verbatim in
 * {@code hugmesh-actions} ({@code ReservedNames}); the two copies MUST
 * be kept identical. When a new dedicated route prefix is added to the
 * gateway, add its first path segment here (and there) — see
 * {@link #firstSegment(String)} / the admin route-access validation, which
 * is the place a new prefix would be introduced.
 */
public final class ReservedNames {

    private ReservedNames() {}

    /**
     * Canonical reserved labels — case-insensitive. A username (after
     * {@link #normalize(String)}) must not equal any of these. Keep this
     * block byte-for-byte identical to the copy in hugmesh-actions.
     */
    public static final Set<String> RESERVED = Set.of(
            // fe-gateway route prefixes
            "admin", "apidocs", "be", "bff", "_fragments", "fragments",
            "login", "logout", "mod", "user", "users",
            // superadmin: TAILNET superadmin App-Store console route prefix
            // (/superadmin/appstore/** on the superadmin-gateway)
            "superadmin",
            // hmdm / attest: the Headwind MDM (/hmdm/manage/**, /hmdm/rest/**)
            // and AttestationServer (/attest/auditor/**, /attest/api/**)
            // tailnet-only superadmin-gateway route prefixes (canonical
            // reserved-prefixes.yaml rev 7/8 — the canonical YAML instructed
            // the app-repo copies to add these when the routes shipped)
            "hmdm", "attest",
            // character-studio: the Character Studio (VN) micro-frontend remote,
            // served at /character-studio/** on the fe-gateway
            // (apps/20-gateway-fe.yaml route[character-studio-ui].path)
            "character-studio",
            // character-forge: the Character Forge (3D) micro-frontend remote,
            // served at /character-forge/** on the fe-gateway (BFF at
            // /bff/character-forge/**) — canonical reserved-prefixes.yaml rev 9
            "character-forge",
            // be-gateway route prefixes + publicly-routable homeserver surfaces
            // (_synapse: /_synapse/** Matrix Synapse-compat; media: /media/** Mastodon)
            "api", "_matrix", "matrix", "_synapse", "media", "mastodon", "pleroma",
            "forum", "phpbb", "oauth", "oauth2",
            // edge-AI routes: ai.hugmesh.net (the edge-AI inference tier
            // host, route[edge-ai].host) + /v1/analyze/** (the edge-AI analysis
            // API path, route[edge-ai-analysis].path, both apps/20-gateway-be.yaml)
            "ai", "v1",
            // optional-service route prefixes / reserved subdomains: LocalTube
            // (/tube/content/** route-access seed) + the optional video/wiki services
            // (owncast/wiki ride /bff/** + /social/wiki/**; reserved so a vanity
            // owncast./wiki. handle can never collide)
            "tube", "owncast", "wiki",
            // reserved subdomains
            "id", "auth", "scale", "headscale", "www",
            // defensive web / infra names
            "root", "static", "assets", "public", "health", "healthz",
            "actuator", "metrics", "well-known", "favicon", "robots",
            "sitemap", "status", "support", "help", "social", "gm",
            "pki", "vault", "argocd", "gitlab", "registry",
            // FE webroot static / module-federation manifest filenames (fe-gateway
            // anonymous-SPA-shell rows, distinct literal first-segments from the
            // already-reserved bare "favicon" label above). Stored lower-case
            // (like every other entry here) though the canonical spec/on-disk
            // filename is "remoteEntry.json" — this set's match is documented
            // case-insensitive and isReserved() always lower-cases the candidate.
            "index.html", "favicon.ico", "importmap.json", "remoteentry.json",
            // NOTE: the neutral @system notification SENDER (Notifications PR3) is reserved
            // via the SEPARATE RESERVED_PLATFORM_INTERNAL set below — NOT this canonical
            // cross-repo RESERVED block — so it stays out of the size-82 canonical-sync
            // contract while isReserved on the @system handle still fails closed.
            // (Do NOT quote that handle as a string literal here: the canonical
            // reserved-prefix validator harvests every quoted token inside this
            // Set.of(...) initializer, so a quoted example would be mis-read as a
            // reserved label and falsely flagged as drift against the canonical YAML.)
            // hugmesh.games app prefixes (derived from the games nginx
            // /_remotes/<slug>/ blocks + location prefixes + the
            // <service>.hugmesh.games subdomains) — kept byte-for-byte in
            // sync with the canonical RESERVED_LABELS in hugmesh-federation-api
            // / hugmesh-user-bff-api so a games-prefix username can never be
            // minted here but rejected at the profile/DB layer (or vice-versa).
            "games", "play", "wasm", "producer", "publisher", "banned",
            "api-docs", "docs", "_remotes", "producer-registration",
            "registration", "wasm-fragment", "games-dodecahedron",
            "games-rpg-maker", "games-three-wizards", "games-vn-maker",
            "games-instances-console",
            // games-character-forge / games-shadows-of-the-net: the 3D character
            // maker + the XR chat room published into hugmesh.games as wasm
            // games (nginx /_remotes/<slug>/ blocks, existing games-* pattern) —
            // canonical reserved-prefixes.yaml rev 9
            "games-character-forge", "games-shadows-of-the-net");

    /**
     * PLATFORM-INTERNAL reserved labels — names the PLATFORM ITSELF mints and which
     * therefore must never be claimable by a human-provisioned identity, but which are
     * NOT part of the cross-repo {@link #RESERVED} canonical-sync contract (so adding one
     * here does NOT change the size-82 canonical guard, nor require a byte-for-byte edit
     * to the four sibling {@code ReservedNames} copies).
     *
     * <p>{@code system} is the per-domain neutral {@code @system} notifications sender
     * (Notifications PR3): each domain provisions a Casdoor {@code system} account that
     * sends account-status / infra / feature notifications. The whole reason to reserve
     * it is so ONLY the platform's own notification provisioner can mint it — via
     * {@link net.hugmesh.authcore.casdoor.CasdoorAdminClient#ensureLiteralUser},
     * the one call in this jar that bypasses the reserved/confusable gate for a literal,
     * platform-owned username — a human registering {@code system} would be impersonating
     * the neutral sender. {@link #isReserved(String)} consults this set too, so the
     * username gate + the admin/provision layer both fail-CLOSED on it.
     */
    public static final Set<String> RESERVED_PLATFORM_INTERNAL = Set.of("system");

    /**
     * Normalise a candidate username to the DNS-label form the vanity
     * subdomain uses, so a reserved label cannot be smuggled past the check
     * with case/Unicode/separator tricks:
     *
     * <ul>
     *   <li>Unicode NFKC fold (so full-width / compatibility forms collapse
     *       onto their ASCII equivalents);</li>
     *   <li>trim + lower-case (the check is case-insensitive);</li>
     *   <li>collapse any run of non-{@code [a-z0-9]} characters to a single
     *       {@code -} (mirrors how the vanity subdomain slugifies a handle —
     *       {@code _matrix}, {@code well.known}, {@code well known} all fold
     *       to the same DNS label) and strip leading/trailing {@code -}.</li>
     * </ul>
     *
     * <p>Returns "" for a null/blank input.
     */
    public static String normalize(String raw) {
        if (raw == null) return "";
        String n = Normalizer.normalize(raw, Normalizer.Form.NFKC).trim().toLowerCase();
        // Collapse separators (incl. '_' and '.') to '-' so the label matches
        // the slug a vanity subdomain would derive, then trim stray dashes.
        n = n.replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
        return n;
    }

    /**
     * True if {@code username} (once normalised) collides with a reserved
     * label. Compares both the normalised form AND a dash-stripped form so a
     * leading-underscore route prefix such as {@code _matrix}/{@code _fragments}
     * (which normalises to {@code matrix}/{@code fragments}) is still caught
     * regardless of how the raw label was punctuated.
     */
    public static boolean isReserved(String username) {
        if (username == null) return false;
        // Raw lower-cased form catches the underscore-prefixed labels that are
        // stored verbatim in the set (_matrix, _fragments, _remotes) — normalise()
        // collapses their leading '_' away, so the literal must be matched too.
        String raw = username.trim().toLowerCase();
        if (RESERVED.contains(raw) || RESERVED_PLATFORM_INTERNAL.contains(raw)) return true;
        String n = normalize(username);
        if (n.isEmpty()) return false;
        if (RESERVED.contains(n) || RESERVED_PLATFORM_INTERNAL.contains(n)) return true;
        // The underscore-prefixed prefixes (_matrix, _fragments) normalise to
        // their dash-free core; compare that against the reserved set too.
        String collapsed = n.replace("-", "");
        return RESERVED.contains(collapsed) || RESERVED_PLATFORM_INTERNAL.contains(collapsed);
    }

    // ── Route-prefix helpers (admin-bff side only) ─────────────────────────

    /**
     * The first path segment of a gateway path/pattern, in the same
     * normalised DNS-label form {@link #normalize(String)} produces. Strips a
     * leading {@code /}, drops everything from the next {@code /}, drops a
     * trailing Ant wildcard, and normalises the remainder. Examples:
     * {@code /api/admin/**} → {@code api}, {@code /_matrix/**} → {@code matrix},
     * {@code /bff/login} → {@code bff}, {@code /} → {@code ""}.
     */
    public static String firstSegment(String path) {
        if (path == null) return "";
        String p = path.trim();
        while (p.startsWith("/")) p = p.substring(1);
        int slash = p.indexOf('/');
        if (slash >= 0) p = p.substring(0, slash);
        // Drop a bare wildcard segment (/** or /*).
        if (p.equals("**") || p.equals("*")) return "";
        return normalize(p);
    }

    /**
     * True when a gateway path's first segment is a reserved/dedicated
     * prefix. Used by the admin route-access CRUD to recognise that a rule
     * targets a dedicated prefix (so the reserved set stays the source of
     * truth) and to warn when a NEW first segment is introduced that is not
     * yet in {@link #RESERVED}.
     */
    public static boolean isReservedPrefix(String path) {
        String seg = firstSegment(path);
        return !seg.isEmpty() && isReserved(seg);
    }
}

package systems.snapdragon.authcore.account;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Durable, R2DBC-backed account + session + grant + allowlist store. The reactive
 * production replacement for the old in-memory {@code ConcurrentHashMap} store:
 * the admin-managed Gmail/Discord allowlist, the two-stage account lifecycle, the
 * per-user namespace grants, and the opaque BFF session tokens the admin-ui /
 * login-ui carry as {@code Authorization: Bearer <bffToken>} now all live in the
 * config Postgres (schema in Liquibase {@code db/changelog}). State is therefore
 * durable across restarts AND shared across replicas — no per-pod state is lost.
 *
 * <p>This is the BFF's <em>application-level</em> session layer. It is deliberately
 * distinct from the Casdoor OAuth2 resource-server filter chain
 * ({@code SecurityConfig}), which independently validates the Casdoor JWT minted
 * by the pki gateway — defence in depth.
 *
 * <p>Backed by Spring Data R2DBC repositories ({@link AllowlistRepository},
 * {@link AccountRowRepository}, {@link BffSessionRepository},
 * {@link NamespaceGrantRepository}) — no raw {@code DatabaseClient}. All datastore
 * access returns {@link Mono}/{@link Flux} (non-blocking). Sessions are short-lived
 * ({@code expires_at}) so a restart / replica does not drop a live session and stale
 * rows are reaped lazily on read.
 */
@Component
public class AccountStore {

    private static final Logger log = LoggerFactory.getLogger(AccountStore.class);
    private static final SecureRandom RNG = new SecureRandom();

    /** Session TTL — short-lived but durable; survives a restart within the window. */
    static final Duration SESSION_TTL = Duration.ofHours(12);

    /** The platform namespaces an admin can grant a user access to. */
    public static final List<String> NAMESPACES = List.of(
            "snapdragon-pki", "snapdragon-backend", "snapdragon-frontend",
            "snapdragon-games", "observability");

    private final AllowlistRepository allowlist;
    private final AccountRowRepository accounts;
    private final BffSessionRepository sessions;
    private final NamespaceGrantRepository grants;
    private final Set<String> admins;

    public AccountStore(AllowlistRepository allowlist,
                        AccountRowRepository accounts,
                        BffSessionRepository sessions,
                        NamespaceGrantRepository grants,
                        @Value("${app.admin-emails:admin@snapdragon.systems}") String adminEmails) {
        this.allowlist = allowlist;
        this.accounts = accounts;
        this.sessions = sessions;
        this.grants = grants;
        this.admins = new java.util.HashSet<>();
        for (String e : adminEmails.split(",")) {
            String t = e.trim().toLowerCase();
            if (!t.isEmpty()) admins.add(t);
        }
    }

    /**
     * Seed the admin emails into the durable allowlist on startup (idempotent
     * upsert). Blocks intentionally — runs once at boot, off the request path.
     */
    @PostConstruct
    public void seedAdmins() {
        try {
            for (String email : admins) {
                inviteEmail(email).block(Duration.ofSeconds(10));
            }
            log.info("[account-store] seeded {} admin email(s) into the durable allowlist", admins.size());
        } catch (Exception e) {
            log.warn("[account-store] admin-email seed skipped (datastore unavailable): {}", e.toString());
        }
    }

    // ── Allowlist (admin-managed) ──────────────────────────────────────
    public Flux<String> allowedEmails() {
        return allowlist.findByProviderOrderByHandle("google").map(Allowlist::handle);
    }

    public Flux<String> allowedDiscord() {
        return allowlist.findByProviderOrderByHandle("discord").map(Allowlist::handle);
    }

    public Mono<Boolean> isEmailInvited(String email) {
        return isInvited("google", email);
    }

    public Mono<Boolean> isDiscordInvited(String handle) {
        return isInvited("discord", handle);
    }

    private Mono<Boolean> isInvited(String provider, String handle) {
        return allowlist.existsByProviderAndHandle(provider, handle.toLowerCase());
    }

    public Mono<Void> inviteEmail(String email)    { return invite("google", email); }
    public Mono<Void> inviteDiscord(String handle) { return invite("discord", handle); }

    private Mono<Void> invite(String provider, String handle) {
        // Portable upsert: insert only if absent (composite PK), so a re-invite is a no-op.
        return allowlist.insertIfAbsent(provider, handle.toLowerCase()).then();
    }

    public Mono<Void> revokeEmail(String email)    { return revokeFromAllowlist("google", email); }
    public Mono<Void> revokeDiscord(String handle) { return revokeFromAllowlist("discord", handle); }

    private Mono<Void> revokeFromAllowlist(String provider, String handle) {
        return allowlist.deleteByProviderAndHandle(provider, handle.toLowerCase()).then();
    }

    // ── Accounts (two-stage registration lifecycle) ────────────────────
    public static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase();
    }

    /** Get-or-create the account for an invited identity (registrationComplete=false). */
    public Mono<Account> ensureAccount(String provider, String handle) {
        String h = handle.toLowerCase();
        String id = idFor(provider, h);
        List<String> roles = ("google".equals(provider) && admins.contains(h))
                ? List.of("user", "admin") : List.of("user");
        String rolesCsv = String.join(",", roles);
        return account(id).switchIfEmpty(
                accounts.save(new AccountRow(id, provider, h, false, rolesCsv, LocalDateTime.now(), true))
                        .thenReturn(new Account(id, provider, h, false, roles)));
    }

    public Mono<Account> account(String id) {
        return accounts.findById(id).map(AccountStore::toAccount);
    }

    /** (Re)start onboarding: reset registrationComplete to false. */
    public Mono<Account> restartOnboarding(Account a) {
        return setComplete(a, false);
    }

    /** Stage 2: mark complete (entitles service-token brokering). */
    public Mono<Account> markComplete(Account a) {
        return setComplete(a, true);
    }

    private Mono<Account> setComplete(Account a, boolean complete) {
        String rolesCsv = a.roles() == null ? "user" : String.join(",", a.roles());
        return accounts.save(new AccountRow(
                        a.id(), a.provider(), a.handle(), complete, rolesCsv, LocalDateTime.now(), false))
                .thenReturn(a.withRegistrationComplete(complete));
    }

    // ── Opaque BFF sessions (the Bearer token the UIs carry) ───────────
    public Mono<String> newSession(Account a) {
        String token = "bff_" + randomToken();
        LocalDateTime expires = LocalDateTime.now().plus(SESSION_TTL);
        return sessions.save(new BffSession(
                        token, a.id(), LocalDateTime.now(), expires, false, null, null, true))
                .thenReturn(token);
    }

    /**
     * Resolve the current account from the raw {@code Authorization} header value.
     * Delegates to {@link #sessionOfToken(String)} after stripping the {@code Bearer }
     * prefix so the cookie carrier and this header carrier resolve to the SAME lookup.
     */
    public Mono<Account> sessionOf(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return Mono.empty();
        }
        return sessionOfToken(authorizationHeader.substring(7).trim());
    }

    /**
     * Resolve the current account from a RAW opaque session token (no {@code Bearer }
     * prefix). A non-{@code bff_} token, an unknown token, or an expired row all resolve
     * to empty (expired rows are lazily reaped).
     */
    public Mono<Account> sessionOfToken(String token) {
        if (token == null || !token.startsWith("bff_")) return Mono.empty();
        return sessions.findById(token)
                .flatMap(s -> {
                    LocalDateTime exp = s.expiresAt();
                    if (exp != null && exp.isBefore(LocalDateTime.now())) {
                        // Lazily reap the expired row, then resolve to empty.
                        return sessions.deleteById(token).then(Mono.empty());
                    }
                    return account(s.accountId());
                });
    }

    /**
     * MFA-satisfaction state of an opaque session for the A5 step-up leg + the
     * {@code GET /bff/session} hydration. Empty Mono for an unknown/expired token (caller
     * treats absence as NOT satisfied — fail-closed).
     */
    public Mono<MfaState> mfaStateOf(String token) {
        if (token == null || !token.startsWith("bff_")) return Mono.empty();
        return sessions.findById(token)
                .flatMap(s -> {
                    LocalDateTime exp = s.expiresAt();
                    if (exp != null && exp.isBefore(LocalDateTime.now())) {
                        return Mono.empty();
                    }
                    return Mono.just(new MfaState(s.mfaSatisfied(), s.mfaSatisfiedAt()));
                });
    }

    /**
     * Stamp a FRESH MFA satisfaction onto an opaque session. Returns the rows updated
     * (0 = unknown token).
     */
    public Mono<Long> stampMfaSatisfied(String token, String amr) {
        if (token == null || !token.startsWith("bff_")) return Mono.just(0L);
        return sessions.stampMfaSatisfied(token, amr == null ? "" : amr);
    }

    /**
     * Delete the opaque session row for {@code token} — the logout primitive. Idempotent.
     * Returns the account_id that was logged out (empty if the token did not resolve).
     */
    public Mono<String> deleteSession(String token) {
        if (token == null || !token.startsWith("bff_")) return Mono.empty();
        return sessions.findById(token)
                .flatMap(s -> sessions.deleteById(token).thenReturn(s.accountId()));
    }

    /**
     * Clear the MFA satisfaction on an opaque session — the single-use consumption the A5
     * step-up leg performs per privileged mutation. Idempotent.
     */
    public Mono<Long> clearMfaSatisfied(String token) {
        if (token == null || !token.startsWith("bff_")) return Mono.just(0L);
        return sessions.clearMfaSatisfied(token);
    }

    /** The MFA-satisfaction snapshot of an opaque session (the A5 freshness leg input). */
    public record MfaState(boolean satisfied, LocalDateTime satisfiedAt) {
    }

    // ── Per-user namespace grants ──────────────────────────────────────
    public Mono<List<String>> namespacesFor(Account a) {
        if (a.isAdmin()) return Mono.just(new ArrayList<>(NAMESPACES));
        return grants.findByGranteeOrderByNamespace(a.id().toLowerCase())
                .map(NamespaceGrant::namespace).collectList();
    }

    public Mono<List<Map<String, Object>>> allGrants() {
        return grants.findAllByOrderByGranteeAscNamespaceAsc()
                .collectList()
                .map(rows -> {
                    // Group namespaces per grantee, preserving first-seen order.
                    Map<String, List<String>> byUser = new LinkedHashMap<>();
                    for (NamespaceGrant r : rows) {
                        byUser.computeIfAbsent(r.grantee(), k -> new ArrayList<>()).add(r.namespace());
                    }
                    List<Map<String, Object>> out = new ArrayList<>();
                    byUser.forEach((user, ns) -> {
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("user", user);
                        row.put("namespaces", ns);
                        out.add(row);
                    });
                    return out;
                });
    }

    public boolean isValidNamespace(String ns) { return NAMESPACES.contains(ns); }

    public Mono<Void> grant(String user, String namespace) {
        return grants.insertIfAbsent(user.toLowerCase(), namespace).then();
    }

    public Mono<Void> revoke(String user, String namespace) {
        return grants.deleteByGranteeAndNamespace(user.toLowerCase(), namespace).then();
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private static Account toAccount(AccountRow row) {
        String rolesCsv = row.roles();
        List<String> roles = (rolesCsv == null || rolesCsv.isBlank())
                ? List.of("user")
                : Arrays.stream(rolesCsv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        return new Account(row.id(), row.provider(), row.handle(), row.registrationComplete(), roles);
    }

    /** Session-token entropy width in bytes (>=32 = 256-bit CSPRNG). Public so consumers/tests
     *  can reason about the encoded token length without hardcoding it. */
    public static final int SESSION_TOKEN_BYTES = 32;

    /** Generate a URL-safe, unpadded base64 CSPRNG token of {@link #SESSION_TOKEN_BYTES} bytes.
     *  Public utility on the shared auth core (also the body of the opaque {@code bff_} session id). */
    public static String randomToken() {
        byte[] b = new byte[SESSION_TOKEN_BYTES];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Test/visibility helper: the configured admin emails. */
    public Set<String> admins() { return new java.util.HashSet<>(admins); }

    /** Convenience for callers that pass a comma list. */
    static List<String> split(String csv) {
        return Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}

package systems.snapdragon.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.username.UsernameGate;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reactive wrapper around the parts of the Casdoor admin API the BFF needs to make
 * "invite a user" actually CREATE/enable the real identity in Casdoor (not just a
 * local allowlist row). Modeled on snapdragon-actions {@code CasdoorClient}:
 * {@link WebClient} with HTTP Basic ({@code clientId:clientSecret}) on every call.
 *
 * <p>Primitives:
 * <ul>
 *   <li>{@link #ensureUser} — get-user then add-user (or update-user to clear
 *       {@code isForbidden}); the real identity for an invited Gmail/Discord.</li>
 *   <li>{@link #disableUser} — update-user {@code isForbidden=true}.</li>
 *   <li>{@link #addUserToRole} / {@link #removeUserFromRole} — get-role +
 *       update-role whole-list replace (Casdoor has no add-one-member call).</li>
 * </ul>
 *
 * <p>The exact add-user / update-role payload is version-specific (the manifests
 * carry a "validate against the deployed casdoor-all-in-one" caveat); this client
 * implements the documented shape and is gated behind {@code casdoor.admin.enabled}
 * by its caller so a Casdoor-less run never fails.
 */
public class CasdoorAdminClient {

    private static final Logger log = LoggerFactory.getLogger(CasdoorAdminClient.class);

    private final WebClient http;
    private final String organization;
    private final String signupApplication;
    /**
     * The username-derivation GATE applied to the username derived from the
     * provider handle BEFORE any add-user / enable write. Null is allowed (the
     * derived username is then used verbatim) so the existing test seam + a
     * gate-less wiring keep working; the production wiring always supplies it.
     */
    @Nullable
    private final UsernameGate usernameGate;

    public CasdoorAdminClient(String baseUrl, String clientId, String clientSecret,
                              String organization, String signupApplication,
                              @Nullable UsernameGate usernameGate) {
        this(WebClient.builder()
                        .baseUrl(baseUrl)
                        .defaultHeader("Authorization", "Basic "
                                + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()))
                        .build(),
                organization, signupApplication, usernameGate);
    }

    /** Test seam — inject a pre-built WebClient (e.g. backed by a stub exchange). */
    CasdoorAdminClient(WebClient http, String organization, String signupApplication) {
        this(http, organization, signupApplication, null);
    }

    CasdoorAdminClient(WebClient http, String organization, String signupApplication,
                       @Nullable UsernameGate usernameGate) {
        this.http = http;
        this.organization = organization;
        this.signupApplication = signupApplication;
        this.usernameGate = usernameGate;
    }

    public String organization() { return organization; }

    /**
     * Create-or-enable the Casdoor user for an invited identity, then ensure each
     * role's membership. Idempotent: if the user exists it is enabled
     * ({@code isForbidden=false}); otherwise it is added. {@code roles} is the
     * lowercase set (e.g. {@code ["user"]} / {@code ["user","admin"]}); each maps
     * to a Casdoor role {@code ROLE_<UPPER>}.
     */
    public Mono<Void> ensureUser(String provider, String handle, String email, List<String> roles) {
        String derived = usernameOf(provider, handle);
        // SERVICE-LAYER GATE (defence-in-depth): the username derived from the
        // provider handle is checked against the federation confusable/skeleton
        // engine + the local reserved fast-path BEFORE any add-user / enable
        // write. A reserved/confusable collision is rejected or auto-disambiguated
        // to a mintable variant (alice → alice2 …). When no gate is wired the
        // derived username is used verbatim (test seam / gate-less run).
        return gatedUsername(derived).flatMap(username ->
                // getUser emits the user map when present and completes empty when absent
                // (get-user error / null data). Present → update-user to clear isForbidden;
                // absent → add-user. switchIfEmpty covers the absent branch.
                getUser(username)
                        .flatMap(existing -> setForbidden(username, email, false).thenReturn(existing))
                        .switchIfEmpty(addUser(username, email).then(Mono.just(Map.<String, Object>of())))
                        .then(ensureRoles(username, roles))
                        .doOnSuccess(v -> log.info("[casdoor] ensured user {}/{} (+{} role(s))",
                                organization, username, roles == null ? 0 : roles.size())));
    }

    /**
     * Create-or-enable a PLATFORM-INTERNAL Casdoor account by its LITERAL username,
     * BYPASSING the username-derivation gate. This is the narrow path the
     * notifications {@code @system} sender provisioner uses (Notifications PR3): the
     * {@code system} name is RESERVED precisely so no human identity can claim it, which
     * means {@link #ensureUser} — which runs {@code username} through the reserved/
     * confusable gate — would (correctly) REJECT it. Provisioning the platform's OWN
     * reserved account is the one legitimate case that must skip that gate, so it uses
     * the verbatim username here.
     *
     * <p>Idempotent exactly like {@link #ensureUser}: present → enable
     * ({@code isForbidden=false}); absent → add; then ensure each role's membership.
     * {@code roles} is the lowercase least-privilege set the caller passes (for
     * {@code @system}: {@code user}, {@code matrix}, {@code mastodon} — NEVER admin).
     *
     * @param username the literal Casdoor username to mint (e.g. {@code system})
     * @param email    the account email (e.g. {@code system@<domain>}), may be null
     * @param roles    the lowercase least-privilege role set (never includes admin)
     */
    public Mono<Void> ensureLiteralUser(String username, String email, List<String> roles) {
        String name = username == null ? "" : username.trim().toLowerCase();
        return getUser(name)
                .flatMap(existing -> setForbidden(name, email, false).thenReturn(existing))
                .switchIfEmpty(addUser(name, email).then(Mono.just(Map.<String, Object>of())))
                .then(ensureRoles(name, roles))
                .doOnSuccess(v -> log.info("[casdoor] ensured platform-internal user {}/{} (+{} role(s))",
                        organization, name, roles == null ? 0 : roles.size()));
    }

    /**
     * Resolve the gated, mintable username for a derived candidate. With a gate
     * wired this rejects reserved names and auto-disambiguates confusable/exact
     * collisions; with no gate (test seam) it passes the candidate through.
     */
    private Mono<String> gatedUsername(String derived) {
        return usernameGate == null ? Mono.just(derived) : usernameGate.resolve(derived);
    }

    /** Disable (forbid) a Casdoor user — the invite was cleared. */
    public Mono<Void> disableUser(String provider, String handle) {
        String username = usernameOf(provider, handle);
        return setForbidden(username, null, true)
                .doOnSuccess(v -> log.info("[casdoor] disabled user {}/{}", organization, username));
    }

    // ── User primitives ────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    Mono<Map<String, Object>> getUser(String username) {
        return http.get()
                .uri(uri -> uri.path("/api/get-user").queryParam("id", organization + "/" + username).build())
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> {
                    Object data = body.get("data");
                    return data instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
                })
                .defaultIfEmpty(Map.of())
                .map(m -> m.isEmpty() ? null : m)
                // A 404 / null-data means "no such user" — treat as absent, not error.
                .onErrorResume(e -> {
                    log.debug("[casdoor] get-user {} treated as absent: {}", username, e.toString());
                    return Mono.empty();
                });
    }

    Mono<Void> addUser(String username, String email) {
        Map<String, Object> user = userObject(username, email, false);
        return http.post()
                .uri("/api/add-user")
                .bodyValue(user)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("add-user", username, r))
                .then();
    }

    Mono<Void> setForbidden(String username, String email, boolean forbidden) {
        Map<String, Object> user = userObject(username, email, forbidden);
        return http.post()
                .uri(uri -> uri.path("/api/update-user").queryParam("id", organization + "/" + username).build())
                .bodyValue(user)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("update-user", username, r))
                .then();
    }

    // ── D8 MFA Property write (the ADVISORY raw-JWT carrier) ────────────
    /**
     * Stamp the user's {@code mfa_satisfied_at} Casdoor Property to {@code epochMillis}
     * (the ADVISORY user-scoped half of the A4 dual-stamp; the AUTHORITATIVE half is the
     * {@code bff_session} row). Casdoor stores {@code User.properties} as a Go
     * {@code map[string]string}, so the value is written as a NUMERIC STRING (e.g.
     * {@code "1750233600000"}) — this is exactly the flat top-level snake_case
     * {@code mfa_satisfied_at} claim the gateway's {@code Roles.isMfaSatisfied} reads off
     * a freshly-minted JWT-Custom token.
     *
     * <h3>GET-then-MERGE (sibling-preserving) — load-bearing</h3>
     * Casdoor's {@code update-user} REPLACES the whole user object, so a naive write would
     * clobber {@code isAdmin}/{@code name}/{@code email} and any sibling Properties. We
     * therefore (1) GET the current user, (2) MERGE only the {@code mfa_satisfied_at} key
     * into a COPY of the existing {@code properties} map (preserving every sibling), and
     * (3) POST {@code update-user} with {@code &columns=properties} so ONLY the properties
     * column is updated (the {@code columns} param is the load-bearing guard against the
     * controller clobbering other columns). Absent user / GET failure -> no-op (the
     * authoritative session stamp already landed; this advisory write is best-effort).
     *
     * @param username    the Casdoor username (org/username id is built here)
     * @param epochMillis the MFA-success timestamp in epoch millis
     */
    public Mono<Void> writeMfaProperty(String username, long epochMillis) {
        return mergeMfaProperty(username, Long.toString(epochMillis));
    }

    /**
     * CLEAR the user's {@code mfa_satisfied_at} Casdoor Property (logout / cross-session
     * bleed bound). Removes ONLY that key (sibling Properties preserved) via the same
     * GET-then-MERGE + {@code &columns=properties} path. No-op for an absent user.
     */
    public Mono<Void> clearMfaProperty(String username) {
        return mergeMfaProperty(username, null);
    }

    // ── Registration displayName write (the human-visible Casdoor name) ─
    /**
     * Update the Casdoor user's {@code displayName} (the human-visible name) to the
     * registration-supplied value for the identity {@code provider:handle}. This is the
     * Casdoor leg of the registration display-name forwarding: the {@code add-user} at
     * invite time seeds {@code displayName=username} (see {@link #userObject}), so a
     * freshly-registered principal who supplied a chosen display name has it recorded on
     * the Casdoor account here.
     *
     * <h3>GET-then-MERGE (sibling-preserving) + {@code &columns=display_name}</h3>
     * Identical contract to {@link #mergeMfaProperty}: Casdoor's {@code update-user}
     * REPLACES the whole user object, so we (1) GET the current user, (2) set ONLY the
     * {@code displayName} key on a COPY of the existing object (preserving every other
     * column + sibling Properties), and (3) POST {@code update-user} with
     * {@code &columns=display_name} so ONLY the displayName column is persisted (the
     * {@code columns} param is the load-bearing guard against clobbering other columns).
     *
     * <p>BEST-EFFORT: an absent user / GET failure / transport error is a NO-OP (logged,
     * swallowed) — recording the display name is enrichment and MUST NEVER fail
     * registration (the account + session are already durable; the user-bff profile is the
     * primary store for the spoken/visible names). The derived username goes through the
     * SAME {@link #usernameOf} derivation the invite-time {@code ensureUser} used, so the
     * GET resolves the same identity. No-op for a blank display name.
     *
     * @param provider    the identity provider ({@code google} / {@code discord})
     * @param handle      the provider handle (gmail address / discord username)
     * @param displayName the human-visible name to record (UTF-8); blank = no-op
     */
    public Mono<Void> updateDisplayName(String provider, String handle, String displayName) {
        if (displayName == null || displayName.isBlank()) return Mono.empty();
        String username = usernameOf(provider, handle);
        return mergeDisplayName(username, displayName.trim());
    }

    /**
     * GET-then-MERGE the {@code displayName} column: round-trips the existing user object
     * and overwrites ONLY {@code displayName}, then POSTs {@code update-user} restricted to
     * {@code &columns=display_name}. Absent user / error -> best-effort no-op.
     */
    @SuppressWarnings("unchecked")
    private Mono<Void> mergeDisplayName(String username, String displayName) {
        String name = username == null ? "" : username.trim();
        if (name.isEmpty()) return Mono.empty();
        return getUser(name)
                .flatMap(existing -> {
                    // COPY the existing user object so the whole row is round-tripped back
                    // (Casdoor update-user replaces the object); &columns=display_name then
                    // restricts the persisted change to the displayName column.
                    Map<String, Object> user = new LinkedHashMap<>(existing);
                    user.put("displayName", displayName);
                    return http.post()
                            .uri(uri -> uri.path("/api/update-user")
                                    .queryParam("id", organization + "/" + name)
                                    .queryParam("columns", "display_name")
                                    .build())
                            .bodyValue(user)
                            .retrieve()
                            .bodyToMono(Map.class)
                            .doOnNext(r -> warnIfNotOk("update-user(display_name)", name, r))
                            .then();
                })
                // Absent user (getUser completes empty) -> nothing to merge.
                .onErrorResume(e -> {
                    log.debug("[casdoor] displayName merge for {} tolerated (best-effort): {}",
                            name, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * GET-then-MERGE the {@code mfa_satisfied_at} Property: a non-null {@code value} sets
     * it, a null {@code value} removes it. Preserves all sibling Properties + all other
     * user columns ({@code &columns=properties} restricts the write to the properties
     * column). Best-effort: an absent user or a transport error resolves empty (the
     * authoritative session stamp is the source of truth; this advisory leg never fails
     * the challenge).
     */
    @SuppressWarnings("unchecked")
    private Mono<Void> mergeMfaProperty(String username, @Nullable String value) {
        String name = username == null ? "" : username.trim();
        if (name.isEmpty()) return Mono.empty();
        return getUser(name)
                .flatMap(existing -> {
                    // COPY the existing user object so the whole row is round-tripped back
                    // (Casdoor update-user replaces the object); &columns=properties then
                    // restricts the persisted change to the properties column.
                    Map<String, Object> user = new LinkedHashMap<>(existing);
                    Object propsRaw = existing.get("properties");
                    Map<String, Object> props = (propsRaw instanceof Map<?, ?> m)
                            ? new LinkedHashMap<>((Map<String, Object>) m)
                            : new LinkedHashMap<>();
                    if (value == null) {
                        props.remove("mfa_satisfied_at");
                    } else {
                        props.put("mfa_satisfied_at", value);
                    }
                    user.put("properties", props);
                    return http.post()
                            .uri(uri -> uri.path("/api/update-user")
                                    .queryParam("id", organization + "/" + name)
                                    .queryParam("columns", "properties")
                                    .build())
                            .bodyValue(user)
                            .retrieve()
                            .bodyToMono(Map.class)
                            .doOnNext(r -> warnIfNotOk("update-user(properties)", name, r))
                            .then();
                })
                // Absent user (getUser completes empty) -> nothing to merge.
                .onErrorResume(e -> {
                    log.debug("[casdoor] mfa-property merge for {} tolerated (best-effort): {}",
                            name, e.toString());
                    return Mono.empty();
                });
    }

    private Map<String, Object> userObject(String username, String email, boolean forbidden) {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("owner", organization);
        user.put("name", username);
        user.put("displayName", username);
        user.put("type", "normal-user");
        user.put("isAdmin", false);
        user.put("isForbidden", forbidden);
        user.put("isDeleted", false);
        if (email != null && !email.isBlank()) user.put("email", email);
        if (signupApplication != null && !signupApplication.isBlank()) {
            user.put("signupApplication", signupApplication);
        }
        return user;
    }

    // ── Role primitives (get-role + update-role whole-list replace) ─────

    /**
     * Ensure a Casdoor ROLE exists (idempotent create) — the per-service identity leg
     * the App-Store {@code AddService} effector needs. Today the client can only
     * {@link #addUserToRole} into a PRE-SEEDED role (the racy get-role→update-role
     * whole-list replace); provisioning a BRAND-NEW service ({@code ROLE_<SERVICE>})
     * requires creating the role first. Maps to Casdoor {@code POST /api/add-role}
     * with the minimal role object ({@code owner,name,displayName}); the role's member
     * list is empty at create (members are added via {@link #addUserToRole}).
     *
     * <p>IDEMPOTENT: a get-role probe first — if the role already exists this is a
     * no-op (no add-role write), so re-running the effector is safe. The
     * {@code roleName} is used VERBATIM (the effector passes the canonical
     * {@code ROLE_<UPPER>} it also seeds into route-access), so this method does NOT
     * re-prefix. Ordering matters (the V7 note): the role must exist BEFORE any
     * {@code addUserToRole}; the effector chains them in that order.
     *
     * @param roleName the literal Casdoor role name (e.g. {@code ROLE_OWNCAST})
     */
    public Mono<Void> createRole(String roleName) {
        String name = roleName == null ? "" : roleName.trim();
        if (name.isEmpty()) {
            return Mono.error(new IllegalArgumentException("roleName is required"));
        }
        return roleExists(name).flatMap(exists -> {
            if (Boolean.TRUE.equals(exists)) {
                log.debug("[casdoor] role {}/{} already exists — add-role skipped", organization, name);
                return Mono.empty();
            }
            Map<String, Object> role = new LinkedHashMap<>();
            role.put("owner", organization);
            role.put("name", name);
            role.put("displayName", name);
            role.put("users", List.of());
            role.put("isEnabled", true);
            return http.post()
                    .uri("/api/add-role")
                    .bodyValue(role)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .doOnNext(r -> warnIfNotOk("add-role", name, r))
                    .doOnSuccess(r -> log.info("[casdoor] created role {}/{}", organization, name))
                    .then();
        });
    }

    /** True iff a role with this exact name exists in the org (a get-role probe whose
     *  {@code data} is non-null). Used by {@link #createRole} for idempotency. */
    Mono<Boolean> roleExists(String roleName) {
        return http.get()
                .uri(uri -> uri.path("/api/get-role").queryParam("id", organization + "/" + roleName).build())
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> body.get("data") instanceof Map<?, ?>)
                .onErrorResume(e -> {
                    log.debug("[casdoor] get-role {} treated as absent: {}", roleName, e.toString());
                    return Mono.just(false);
                })
                .defaultIfEmpty(false);
    }

    /**
     * Delete a Casdoor ROLE (idempotent teardown) — the revoke-roles leg the App-Store
     * expiry/teardown drives. Maps to Casdoor {@code POST /api/delete-role} with the
     * role object; tolerates an already-absent role (a teardown re-run is safe).
     */
    public Mono<Void> deleteRole(String roleName) {
        String name = roleName == null ? "" : roleName.trim();
        if (name.isEmpty()) {
            return Mono.empty();
        }
        Map<String, Object> role = Map.of("owner", organization, "name", name);
        return http.post()
                .uri("/api/delete-role")
                .bodyValue(role)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("delete-role", name, r))
                .doOnSuccess(r -> log.info("[casdoor] deleted role {}/{}", organization, name))
                .then()
                .onErrorResume(e -> {
                    log.debug("[casdoor] delete-role {} tolerated (already absent?): {}", name, e.toString());
                    return Mono.empty();
                });
    }

    Mono<Void> ensureRoles(String username, List<String> roles) {
        if (roles == null || roles.isEmpty()) return Mono.empty();
        Mono<Void> chain = Mono.empty();
        for (String role : roles) {
            String roleName = "ROLE_" + role.trim().toUpperCase();
            chain = chain.then(addUserToRole(roleName, organization + "/" + username));
        }
        return chain;
    }

    @SuppressWarnings("unchecked")
    public Mono<List<String>> getRoleMembers(String roleName) {
        return http.get()
                .uri(uri -> uri.path("/api/get-role").queryParam("id", organization + "/" + roleName).build())
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> {
                    Object data = body.get("data");
                    if (data instanceof Map<?, ?> m && m.get("users") instanceof List<?> list) {
                        return (List<String>) list;
                    }
                    return List.<String>of();
                })
                .onErrorResume(e -> {
                    log.debug("[casdoor] get-role {} empty: {}", roleName, e.toString());
                    return Mono.just(List.of());
                });
    }

    public Mono<Void> addUserToRole(String roleName, String userId) {
        return getRoleMembers(roleName).flatMap(current -> {
            if (current.contains(userId)) return Mono.empty();
            List<String> next = new ArrayList<>(current);
            next.add(userId);
            return updateRoleMembers(roleName, next);
        });
    }

    public Mono<Void> removeUserFromRole(String roleName, String userId) {
        return getRoleMembers(roleName).flatMap(current -> {
            if (!current.contains(userId)) return Mono.empty();
            List<String> next = new ArrayList<>(current);
            next.remove(userId);
            return updateRoleMembers(roleName, next);
        });
    }

    Mono<Void> updateRoleMembers(String roleName, List<String> users) {
        Map<String, Object> body = Map.of("owner", organization, "name", roleName, "users", users);
        return http.post()
                .uri(uri -> uri.path("/api/update-role").queryParam("id", organization + "/" + roleName).build())
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("update-role", roleName, r))
                .then();
    }

    // ── Helpers ────────────────────────────────────────────────────────
    /** Casdoor username for a provider identity: the local-part for Gmail, the
     *  handle for Discord (Casdoor usernames cannot carry '@'). Public so the
     *  API layer can derive + gate the SAME candidate this client would mint. */
    public static String usernameOf(String provider, String handle) {
        String h = handle == null ? "" : handle.trim().toLowerCase();
        if ("google".equals(provider)) {
            int at = h.indexOf('@');
            return at > 0 ? h.substring(0, at) : h;
        }
        return h;
    }

    private static void warnIfNotOk(String op, String subject, Map<?, ?> response) {
        if (response != null && !"ok".equals(response.get("status"))) {
            log.warn("[casdoor] {} for {} returned non-ok: {}", op, subject, response);
        }
    }
}

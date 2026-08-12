package net.hugmesh.authcore.account;

import java.util.List;

/**
 * A registered (Casdoor-backed) account. Mirrors the {@code accounts} entry in
 * the verified reference impl (mock-bff.mjs): a provider-scoped identity that is
 * created at registration stage 1 ({@code registrationComplete=false}) and only
 * flipped to complete at stage 2 — ONLY THEN are the Matrix/Mastodon service
 * tokens released. {@code roles} is the lowercase set the UI/session carries
 * ({@code ["user"]} or {@code ["user","admin"]}); the Casdoor-issued JWT is what
 * the security filter chain independently validates as defence-in-depth.
 */
public record Account(
        String id,                  // "google:alice@x.com" | "discord:bob"
        String provider,            // "google" | "discord"
        String handle,              // email or discord username (lowercased)
        boolean registrationComplete,
        List<String> roles) {       // lowercase: "user", "admin"

    /**
     * Compact constructor — defensively copies the caller-supplied {@code roles} list so the
     * record is genuinely immutable. {@code roles} is authorization-bearing ({@link #isAdmin()}
     * reads it, and BffCookieAuthenticationWebFilter turns it into granted authorities), so a
     * caller retaining a reference to a mutable list it passed in could otherwise flip an
     * account's admin status after construction. {@link List#copyOf} also makes the accessor
     * safe to return directly (it hands back an immutable list, not the internal one).
     *
     * <p>{@code null} is preserved rather than normalised to an empty list: it is a
     * load-bearing "roles unknown / no row" signal that {@code AccountStore.toAccount} and
     * {@code BffCookieAuthenticationWebFilter} both branch on explicitly.
     */
    public Account {
        roles = (roles == null) ? null : List.copyOf(roles);
    }

    public boolean isAdmin() {
        return roles != null && roles.contains("admin");
    }

    public Account withRegistrationComplete(boolean complete) {
        return new Account(id, provider, handle, complete, roles);
    }
}

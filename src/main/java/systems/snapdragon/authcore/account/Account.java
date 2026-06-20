package systems.snapdragon.authcore.account;

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

    public boolean isAdmin() {
        return roles != null && roles.contains("admin");
    }

    public Account withRegistrationComplete(boolean complete) {
        return new Account(id, provider, handle, complete, roles);
    }
}

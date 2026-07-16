package systems.snapdragon.authcore.account;

import java.time.Instant;

/**
 * The BFF-computed account-STATE of a principal, derived from the
 * {@code access_suspension} desired-state table (NOT from the Casdoor token — the
 * BFF never changes token minting). Surfaced on {@code /bff/me} and the
 * {@code /bff/login} response so the host appeal-gate + login-ui can read whether
 * the caller is currently usable.
 *
 * <p>Status vocabulary (one closed set the UI switches on):
 * <ul>
 *   <li>{@code active} — no active suspension on the principal's localpart; the
 *       account is fully usable. {@code until}/{@code reason} are null.</li>
 *   <li>{@code suspended} — a TIMED {@code PROFILE} suspension, or any active
 *       platform-role ({@code ROLE_MATRIX}/{@code ROLE_MASTODON}) suspension. The
 *       account is partially/temporarily curtailed; {@code until} carries the
 *       earliest expiry (null only when a platform-role row is itself permanent).</li>
 *   <li>{@code banned} — a PERMANENT {@code PROFILE} suspension ({@code expires_at}
 *       NULL): the full account is banned with no auto-restore. {@code until} is
 *       null (no expiry); {@code reason} carries the audit reason if any.</li>
 * </ul>
 *
 * <p>The status is computed from the principal's OWN rows only (the suspension is
 * keyed to the person, never the reader's tenant), so it is the same answer
 * regardless of who asks — see admin-bff's {@code SuspensionService#statusFor}
 * (not part of this jar).
 */
public record AccountStatus(String status, Instant until, String reason) {

    public static final String ACTIVE = "active";
    public static final String SUSPENDED = "suspended";
    public static final String BANNED = "banned";

    /** The fully-usable, no-suspension status (null until/reason). */
    public static AccountStatus active() {
        return new AccountStatus(ACTIVE, null, null);
    }

    public boolean isActive() {
        return ACTIVE.equals(status);
    }
}

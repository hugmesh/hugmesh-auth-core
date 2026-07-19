package systems.hugmesh.authcore.username;

/**
 * The result of a federation username-availability check (the shape of
 * {@code GET /api/federation/username/{candidate}/availability} in
 * hugmesh-federation-api, the registry owner of the confusable/skeleton
 * engine).
 *
 * <ul>
 *   <li>{@code candidate} — the username we asked about (echoed back);</li>
 *   <li>{@code available} — true when the candidate may be minted as-is;</li>
 *   <li>{@code reason} — when NOT available, why: {@code exact} (an existing
 *       username with the same skeleton/identity), {@code confusable} (a
 *       look-alike of an existing username), or {@code reserved} (collides
 *       with a reserved label). {@code null}/empty when available;</li>
 *   <li>{@code matchedWith} — the existing username / reserved label the
 *       candidate collides with (diagnostic; may be null).</li>
 * </ul>
 *
 * <p>Defence-in-depth contract: {@code reserved} is NEVER overridable and is
 * fail-CLOSED locally too (the admin-bff {@code ReservedNames} fast-path
 * rejects a reserved candidate before the call is ever made).
 */
public record UsernameAvailability(String candidate, boolean available,
                                   String reason, String matchedWith) {

    /** A clean "available" result — the candidate may be minted as-is. */
    public static UsernameAvailability available(String candidate) {
        return new UsernameAvailability(candidate, true, null, null);
    }

    /** A collision result with the federation-supplied reason + matched name. */
    public static UsernameAvailability collide(String candidate, String reason, String matchedWith) {
        return new UsernameAvailability(candidate, false, reason, matchedWith);
    }

    /** True when the collision is on a reserved label (never overridable). */
    public boolean isReserved() {
        return !available && "reserved".equalsIgnoreCase(reason);
    }
}

package systems.snapdragon.authcore.username;

/**
 * Raised when a username derived from a provider handle cannot be minted: it is
 * reserved, the federation registry flagged it (exact/confusable) and it could
 * not be disambiguated, or the attempt budget was exhausted.
 *
 * <p>Carries the offending {@code candidate} + a machine {@code reason}
 * ({@code reserved}/{@code confusable}/{@code exact}/{@code exhausted}/{@code
 * invalid}/{@code federation-unavailable}) so the API layer can map it to a
 * stable 4xx body.
 */
public class UsernameGateException extends RuntimeException {

    private final String candidate;
    private final String reason;

    public UsernameGateException(String candidate, String reason, String message) {
        super(message);
        this.candidate = candidate;
        this.reason = reason;
    }

    public String candidate() {
        return candidate;
    }

    public String reason() {
        return reason;
    }
}

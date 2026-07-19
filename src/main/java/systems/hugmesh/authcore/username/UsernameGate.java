package systems.hugmesh.authcore.username;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.reserved.ReservedNames;

/**
 * The username-derivation GATE the admin BFF applies to every Casdoor username
 * it is about to mint from a provider handle (a Gmail local-part / Discord
 * handle). Defence-in-depth, in this order:
 *
 * <ol>
 *   <li><b>Local reserved fast-path (fail-CLOSED).</b> {@link ReservedNames}
 *       rejects a candidate that collides with a reserved label WITHOUT a
 *       network call — this is the same backstop the gateway + DB CHECKs
 *       enforce, and it holds even on a federation outage.</li>
 *   <li><b>Federation availability (the confusable/skeleton engine).</b> The
 *       derived username is checked against
 *       {@code GET /api/federation/username/{candidate}/availability} (the
 *       registry owner of the ICU skeleton cache). A {@code reserved}/{@code
 *       exact}/{@code confusable} collision means the candidate cannot be
 *       minted as-is.</li>
 *   <li><b>Reject or auto-disambiguate.</b> On a collision we APPEND a numeric
 *       suffix ({@code alice → alice2 → alice3 …}) and re-check, up to
 *       {@link #MAX_ATTEMPTS}. A reserved collision can never be disambiguated
 *       away (a suffix would still shadow nothing useful and the federation
 *       still answers reserved) — but {@link #reject(...)} is available for the
 *       paths that must HARD-REJECT rather than rename.</li>
 * </ol>
 *
 * <p>{@link #resolve(String)} returns the FIRST mintable username (the original
 * if clean, else a disambiguated variant) or fails with
 * {@link UsernameGateException} if no variant is mintable within the attempt
 * budget. {@link #check(String)} performs the same evaluation WITHOUT renaming
 * (the API-layer guard).
 */
@Service
public class UsernameGate {

    private static final Logger log = LoggerFactory.getLogger(UsernameGate.class);

    /** Disambiguation attempt budget (original + 8 suffixed variants). */
    static final int MAX_ATTEMPTS = 9;

    private final FederationUsernameClient federation;

    public UsernameGate(FederationUsernameClient federation) {
        this.federation = federation;
    }

    /**
     * Evaluate {@code candidate} as-is (no renaming): reject reserved locally,
     * else ask federation. Emits the {@link UsernameAvailability}; the caller
     * (e.g. the API layer) decides whether to 4xx or to disambiguate.
     */
    public Mono<UsernameAvailability> check(String candidate) {
        if (ReservedNames.isReserved(candidate)) {
            // Fail-CLOSED locally; never even reach federation for a reserved name.
            return Mono.just(UsernameAvailability.collide(candidate, "reserved", candidate));
        }
        return federation.availability(candidate);
    }

    /**
     * Return the first mintable username derived from {@code candidate}: the
     * candidate itself if it is clean, otherwise {@code candidate + N} for the
     * smallest {@code N >= 2} that clears the gate. Fails with
     * {@link UsernameGateException} when the candidate is reserved (a reserved
     * label is NEVER auto-renamed — it is a hard policy violation) or when no
     * variant clears within {@link #MAX_ATTEMPTS}.
     */
    public Mono<String> resolve(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return Mono.error(new UsernameGateException(candidate, "invalid",
                    "derived username is blank"));
        }
        if (ReservedNames.isReserved(candidate)) {
            // Reserved is a policy violation, not a collision to rename around.
            return Mono.error(new UsernameGateException(candidate, "reserved",
                    "derived username '" + candidate + "' is a reserved label"));
        }
        return attempt(candidate, candidate, 1);
    }

    private Mono<String> attempt(String base, String candidate, int attemptNo) {
        if (attemptNo > MAX_ATTEMPTS) {
            return Mono.error(new UsernameGateException(base, "exhausted",
                    "no mintable username within " + MAX_ATTEMPTS + " attempts from '" + base + "'"));
        }
        // A disambiguated variant could itself land on a reserved label; re-check.
        if (ReservedNames.isReserved(candidate)) {
            return attempt(base, base + (attemptNo + 1), attemptNo + 1);
        }
        return federation.availability(candidate)
                .flatMap(av -> onAvailabilityResult(base, candidate, attemptNo, av));
    }

    /** Decide the next step given the availability result: accept, reject, or try next variant. */
    private Mono<String> onAvailabilityResult(String base, String candidate, int attemptNo,
                                              UsernameAvailability av) {
        if (av.available()) {
            if (attemptNo > 1) {
                log.info("[username-gate] '{}' collided ({}); disambiguated to '{}'",
                        base, "attempt " + attemptNo, candidate);
            }
            return Mono.just(candidate);
        }
        if (av.isReserved() && candidate.equals(base)) {
            // The federation flags the original as reserved even though our
            // local set did not — honour it as a hard reject (never rename).
            return Mono.error(new UsernameGateException(base, "reserved",
                    "derived username '" + base + "' is reserved (federation)"));
        }
        log.debug("[username-gate] '{}' unavailable ({}); trying next variant",
                candidate, av.reason());
        return attempt(base, base + (attemptNo + 1), attemptNo + 1);
    }
}

package systems.snapdragon.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * FORCE-REFRESH the raw Casdoor JWT after the A4 MFA Property write so the gateway sees
 * the new {@code mfa_satisfied_at} claim WITHIN the freshness window, rather than waiting
 * for the token's natural expiry.
 *
 * <h3>Why this is a seam (and a documented fallback)</h3>
 * The Casdoor {@code mfa_satisfied_at} Property only materialises into a token on a FRESH
 * mint/refresh (a JWT is immutable once issued). The admin-bff, however, is an
 * OPAQUE-SESSION BFF: the public web login bypasses Casdoor's OIDC redirect, so the BFF
 * does NOT hold the user's {@code refresh_token} — it has no credential with which to mint
 * a fresh raw JWT on the user's behalf. Two paths:
 * <ol>
 *   <li><b>Held refresh_token present</b> (a future OIDC-redirect / desktop-PKCE caller
 *       whose refresh_token the BFF custody-holds): exchange it for a fresh access token so
 *       the gateway immediately sees the claim. Wired when that custody lands.</li>
 *   <li><b>Natural-lifetime fallback (TODAY):</b> no held refresh_token -> the existing raw
 *       JWT keeps its claims until it naturally expires; the gateway sees
 *       {@code mfa_satisfied_at} on the NEXT mint/refresh the client performs. GEN2 lowers
 *       the privileged-app {@code expireInHours} precisely so this natural-lifetime gap
 *       stays SHORTER than the MFA freshness window. The AUTHORITATIVE
 *       {@code bff_session.mfa_satisfied} stamp (the source of truth for the four step-up
 *       gates + {@code /bff/session}) is unaffected by this gap — it is immediate. The raw
 *       JWT claim is ADVISORY (raw-brand-traffic only).</li>
 * </ol>
 * Resolving empty in the fallback case keeps the A4 challenge a SUCCESS (the authoritative
 * stamp already landed); this leg NEVER fails the challenge.
 */
@Service
public class RawJwtRefreshService {

    private static final Logger log = LoggerFactory.getLogger(RawJwtRefreshService.class);

    /**
     * Force a fresh raw-JWT mint for {@code subject} if a {@code refreshToken} is held,
     * else apply the documented natural-lifetime fallback (no-op). Best-effort: never
     * fails the challenge.
     *
     * @param subject      the Casdoor subject whose token should refresh
     * @param refreshToken the held refresh_token, or {@code null}/blank when none is custody-held
     */
    public Mono<Void> forceRefresh(String subject, String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            // Natural-lifetime fallback: the BFF holds no refresh_token for this opaque-session
            // caller. The authoritative bff_session stamp already landed; the raw-JWT claim
            // appears on the next natural mint/refresh (bounded by the lowered privileged-app
            // expiry, GEN2).
            log.debug("[mfa-refresh] no held refresh_token for subject -> natural-lifetime fallback "
                    + "(authoritative session stamp is immediate)");
            return Mono.empty();
        }
        // Held-refresh_token path (future custody wiring): exchange refreshToken for a fresh
        // access token so the gateway sees mfa_satisfied_at immediately. Intentionally a
        // best-effort no-op stub until refresh_token custody lands; documented above.
        log.debug("[mfa-refresh] held refresh_token present -> force-refresh path (custody wiring pending)");
        return Mono.empty();
    }
}

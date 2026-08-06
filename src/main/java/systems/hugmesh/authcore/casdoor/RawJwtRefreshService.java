package systems.hugmesh.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
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
 *   <li><b>Natural-lifetime fallback (TODAY, and the ONLY path that ever runs):</b> no held
 *       refresh_token -> the existing raw JWT keeps its claims until it naturally expires;
 *       the gateway sees {@code mfa_satisfied_at} on the NEXT mint/refresh the client
 *       performs. The AUTHORITATIVE {@code bff_session.mfa_satisfied} stamp (the source of
 *       truth for the step-up gates + {@code /bff/session}) is unaffected by this gap — it
 *       is immediate. The raw JWT claim is ADVISORY (raw-brand-traffic only).</li>
 * </ol>
 *
 * <h3>⚠ The GEN2 justification was false, and this path never runs</h3>
 * A previous revision of this javadoc claimed "GEN2 lowers the privileged-app
 * {@code expireInHours} precisely so this natural-lifetime gap stays SHORTER than the MFA
 * freshness window". <b>No such GEN2 change exists</b> ({@code git grep GEN2} in the
 * generator finds an unrelated CI comment and a disk-partitioning note), and no seeded
 * expiry is anywhere near the 10-minute window. Do not restore that reasoning.
 *
 * <p><b>But note what that does NOT imply.</b> {@code expireInHours} bounds how long a
 * STALE token stays valid — it is not a bound on how soon a client may MINT a new one. A
 * caller holding {@code refresh_token} / {@code device_code} / {@code password} can
 * re-mint on demand and pick the claim up immediately; {@code hugmesh-desktop} is seeded
 * as a public PKCE client for exactly that, and says so. So the natural-lifetime fallback
 * is a <b>usability</b> gap, not a lockout: the holder must ACTIVELY refresh after
 * completing MFA, because nothing here does it for them.
 *
 * <p>Path 1 is not merely disabled. {@code MfaChallengeService} is the ONLY caller and it
 * passes a <b>literal {@code null}</b> as {@code refreshToken}, so {@link #forceRefresh}
 * always takes the fallback branch — {@code app.bff.oidc.enabled} is {@code true} on the
 * live BFF pods, so the bean's presence is NOT the blocker, the argument is. Wiring this
 * needs a real token threaded from that call site, not a flag flip. (A second re-mint path
 * bypasses this class entirely: admin-bff {@code InternalAccountController
 * .exchangeSessionRow()} calls {@code oidcExchange.refresh(...)} directly.)
 *
 * <p><b>The population that genuinely cannot satisfy MFA</b> is a pure
 * {@code client_credentials} machine token: {@code mfa_satisfied_at} is a Casdoor <i>user</i>
 * Property and a machine token has no user subject, so there is nothing to stamp and no
 * factor to enrol. The operator-facing taxonomy is in the generator's
 * {@code docs/MFA-ROLLOUT.md} §2.4, pinned by {@code lint:mfa-raw-jwt-posture}.
 *
 * <p>Resolving empty in the fallback case keeps the A4 challenge a SUCCESS (the authoritative
 * stamp already landed); this leg NEVER fails the challenge.
 */
@Service
public class RawJwtRefreshService {

    private static final Logger log = LoggerFactory.getLogger(RawJwtRefreshService.class);

    /**
     * The OIDC token client used to perform the {@code grant_type=refresh_token} leg. Null when
     * {@code app.bff.oidc.enabled=false} (the bean is absent) — the service then takes the
     * documented natural-lifetime fallback. Injected {@link Nullable} so a non-OIDC deployment
     * boots identically to today.
     */
    @Nullable
    private final OidcExchangeClient oidcExchange;

    public RawJwtRefreshService(@Nullable OidcExchangeClient oidcExchange) {
        this.oidcExchange = oidcExchange;
    }

    /**
     * Force a fresh raw-JWT mint for {@code subject} if a {@code refreshToken} is held AND OIDC
     * custody is enabled, else apply the documented natural-lifetime fallback (no-op).
     * Best-effort: NEVER fails the challenge (a refresh error resolves empty — the authoritative
     * {@code bff_session.mfa_satisfied} stamp already landed and is the source of truth).
     *
     * @param subject      the Casdoor subject whose token should refresh
     * @param refreshToken the held refresh_token, or {@code null}/blank when none is custody-held
     */
    public Mono<Void> forceRefresh(String subject, String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank() || oidcExchange == null) {
            // Natural-lifetime fallback: no held refresh_token (opaque-session caller) or OIDC
            // custody disabled. The authoritative bff_session stamp already landed; the raw-JWT
            // claim appears on the CLIENT'S next mint/refresh — which a refresh_token /
            // device_code / password holder can trigger on demand, but which nothing here
            // triggers for them. See the class javadoc: this branch is taken unconditionally
            // today because the only caller passes refreshToken=null.
            log.debug("[mfa-refresh] natural-lifetime fallback "
                    + "(no held refresh_token or OIDC custody off; authoritative session stamp is immediate)");
            return Mono.empty();
        }
        // Held-refresh_token path: exchange refreshToken for a fresh access token so the gateway
        // sees mfa_satisfied_at within the freshness window. Best-effort — the caller (the BFF
        // session-exchange endpoint) is responsible for re-stamping custody with the returned
        // tokens; here we only force the mint and swallow any error.
        return oidcExchange.refresh(refreshToken)
                .doOnNext(t -> log.debug("[mfa-refresh] held refresh_token exchanged -> fresh access token minted"))
                .onErrorResume(e -> {
                    log.debug("[mfa-refresh] refresh leg failed (fail-open, best-effort): {}", e.toString());
                    return Mono.empty();
                })
                .then();
    }
}

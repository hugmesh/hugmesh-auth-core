package systems.hugmesh.authcore.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * A2 COOKIE MINT — builds the {@code Set-Cookie} for the opaque {@code bff_} session token in
 * cookie mode, and the matching EXPIRE cookie for logout. SHIPS DARK behind
 * {@code app.session.cookie.enabled} (DEFAULT false): when the flag is off {@link #enabled()}
 * is false and {@code AuthController} does NOT set any cookie (it returns the token in the body
 * exactly as today). When the flag is ON, login/register/sessionOut additionally Set-Cookie.
 *
 * <h3>Cookie attributes — security posture</h3>
 * <ul>
 *   <li><b>HttpOnly</b> — JS cannot read the session token (mitigates XSS token theft).</li>
 *   <li><b>Secure</b> — sent only over TLS (configurable off for a plain-HTTP local dev run via
 *       {@code app.session.cookie.secure}, DEFAULT true).</li>
 *   <li><b>SameSite=Lax</b> — not sent on cross-site sub-requests (CSRF mitigation; the
 *       double-submit CSRF token, enabled in the SAME flag, is the second layer).</li>
 *   <li><b>Path=/</b> — the whole BFF surface.</li>
 *   <li><b>host-only (NO Domain attribute)</b> — scoped to the EXACT request host (the
 *       validated-issuer brand host). A host-only cookie is NEVER sent to a sibling host, so it
 *       can NEVER wildcard across {@code DOMAIN_} tenants — the per-brand isolation requirement.
 *       We deliberately do NOT set a {@code Domain} attribute (which would broaden to subdomains).</li>
 *   <li><b>Max-Age</b> — the session TTL so the cookie expires with the row.</li>
 * </ul>
 */
@Component
public class SessionCookieService {

    private final boolean enabled;
    private final boolean secure;
    private final Duration ttl;

    public SessionCookieService(
            @Value("${app.session.cookie.enabled:false}") boolean enabled,
            @Value("${app.session.cookie.secure:true}") boolean secure,
            @Value("${app.session.cookie.ttl:PT12H}") Duration ttl) {
        this.enabled = enabled;
        this.secure = secure;
        this.ttl = (ttl == null || ttl.isZero() || ttl.isNegative()) ? Duration.ofHours(12) : ttl;
    }

    /** Whether the cookie MINT (and, in the same flag, CSRF) is armed. */
    public boolean enabled() {
        return enabled;
    }

    /**
     * Build the {@code Set-Cookie} carrying the opaque {@code bff_} session token, host-only
     * (no Domain attribute) so it is scoped to the EXACT brand host of {@code request} and never
     * crosses a tenant boundary. Returns {@code null} when the cookie mode is disabled (the
     * caller then sets no cookie).
     */
    public ResponseCookie mint(ServerHttpRequest request, String token) {
        if (!enabled || token == null || token.isBlank()) {
            return null;
        }
        return ResponseCookie.from(SessionCookieWebFilter.SESSION_COOKIE, token)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Lax")
                .path("/")
                // host-only: NO .domain(...) -> the cookie binds to the exact request host.
                .maxAge(ttl)
                .build();
    }

    /**
     * Build the EXPIRE cookie for logout (same name/path, {@code Max-Age=0}, empty value) so the
     * browser drops the session cookie. Always built when the cookie mode is enabled (logout must
     * clear the cookie even if the caller authenticated via the Bearer header). Returns
     * {@code null} when the cookie mode is disabled.
     */
    public ResponseCookie expire() {
        if (!enabled) {
            return null;
        }
        return ResponseCookie.from(SessionCookieWebFilter.SESSION_COOKIE, "")
                .httpOnly(true)
                .secure(secure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
    }
}

package net.hugmesh.authcore.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * PROD-PROFILE startup guard for the privilege-bearing {@code /bff/internal/**} surface. That
 * prefix is {@code permitAll()} at the Spring layer ({@code SecurityConfig}, the consumer's own
 * — not part of this jar) and the sudo ENTITLEMENT read under it leaks per-(subject, device)
 * sudo state, so in production its ONLY
 * transport boundary is mutual-TLS ({@code server.ssl.enabled=true} +
 * {@code server.ssl.client-auth=need}). If a prod deployment were mis-wired with SSL disabled
 * or client-auth not required, that surface would be served in the clear to anything that could
 * reach the pod — a silent, catastrophic exposure.
 *
 * <p>This bean is wired ONLY under the prod profile ({@code @Profile("!dev & !test")}, the same
 * predicate the prod {@code SecurityWebFilterChain} uses) and FAILS FAST at startup
 * (a {@link SmartInitializingSingleton} throwing during context refresh aborts the boot) when
 * the mTLS preconditions are not met. It is a complete NO-OP in dev/test (the bean is never
 * created there), so local/CI runs on plaintext are unaffected.
 *
 * <p>The {@link InternalTokenWebFilter} is the app-layer second factor; this guard ensures the
 * transport factor (mTLS) is genuinely in force in prod rather than silently absent.
 */
@Component
@Profile("!dev & !test")
public class InternalSurfaceBootGuard implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(InternalSurfaceBootGuard.class);

    private final boolean sslEnabled;
    private final String clientAuth;

    public InternalSurfaceBootGuard(
            @Value("${server.ssl.enabled:false}") boolean sslEnabled,
            @Value("${server.ssl.client-auth:none}") String clientAuth) {
        this.sslEnabled = sslEnabled;
        this.clientAuth = clientAuth == null ? "none" : clientAuth.trim().toLowerCase();
    }

    @Override
    public void afterSingletonsInstantiated() {
        // server.ssl.client-auth is the Spring closed set {none, want, need}; ONLY 'need'
        // (mTLS REQUIRED, client cert mandatory) protects the permitAll() internal surface —
        // 'want' (optional cert) and 'none' (no cert) both leave it open, so they fail the guard.
        if (!sslEnabled || !"need".equals(clientAuth)) {
            throw new IllegalStateException(
                    "REFUSING TO BOOT: the privilege-bearing /bff/internal/** surface is "
                    + "permitAll() and in production MUST be protected by mutual-TLS, but "
                    + "server.ssl.enabled=" + sslEnabled + " and server.ssl.client-auth='"
                    + clientAuth + "' (require ssl.enabled=true + client-auth=need). "
                    + "Set SSL_ENABLED=true and SSL_CLIENT_AUTH=need, or run with the dev/test "
                    + "profile for plaintext.");
        }
        log.info("[internal-surface-guard] mTLS in force for /bff/internal/** "
                + "(ssl.enabled=true, client-auth=need) — boot OK");
    }
}

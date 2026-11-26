package net.hugmesh.authcore.mfa;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.net.URI;

/**
 * Records the browser origin of every request in the Reactor context, so the WebAuthn
 * ceremony can choose its Relying Party per request ({@link WebAuthnRelyingParty},
 * hugmesh-auth-core#39) without every service signature carrying the exchange.
 *
 * <p>Source, in order: the {@code Origin} header (what a browser sends on the POSTs the
 * ceremony uses — exactly the page's scheme, host and port); else
 * {@code X-Forwarded-Proto} + {@code X-Forwarded-Host} from the edge proxy; else the request
 * URI's own scheme/host/port. Reading a header costs nothing, so it runs for every request.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 6)
public class WebAuthnOriginWebFilter implements WebFilter {

    /** The Reactor-context key the origin is stored under. */
    public static final String CONTEXT_KEY = WebAuthnOriginWebFilter.class.getName() + ".origin";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String origin = originOf(exchange.getRequest());
        if (origin == null) {
            return chain.filter(exchange);
        }
        return chain.filter(exchange).contextWrite(ctx -> ctx.put(CONTEXT_KEY, origin));
    }

    /** The request's browser origin, or {@code null} when nothing says. */
    static String originOf(ServerHttpRequest req) {
        HttpHeaders h = req.getHeaders();
        String o = h.getFirst(HttpHeaders.ORIGIN);
        if (o != null && !o.isBlank()) {
            return o.trim();
        }
        String host = first(h.getFirst("X-Forwarded-Host"));
        if (host != null) {
            String proto = first(h.getFirst("X-Forwarded-Proto"));
            return (proto == null ? "https" : proto) + "://" + host;
        }
        URI u = req.getURI();
        if (u.getHost() == null || u.getScheme() == null) {
            return null;
        }
        return u.getScheme() + "://" + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "");
    }

    /** The recorded origin of the current request (from a deferContextual), or null. */
    public static String from(ContextView ctx) {
        return ctx.getOrDefault(CONTEXT_KEY, null);
    }

    private static String first(String csvHeader) {
        if (csvHeader == null || csvHeader.isBlank()) {
            return null;
        }
        String v = csvHeader.split(",")[0].trim();
        return v.isEmpty() ? null : v;
    }
}

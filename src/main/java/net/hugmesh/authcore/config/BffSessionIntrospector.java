package net.hugmesh.authcore.config;

import reactor.core.publisher.Mono;

/**
 * Resolves an opaque {@code bff_} session token to its account/role truth for a service that has
 * no local access to the accounts/bff_session tables. {@link HttpBffSessionIntrospector} is the
 * network implementation; tests or other transports can supply their own.
 *
 * <p>Contract: an UNKNOWN or EXPIRED session completes EMPTY (the caller then passes the request
 * through unauthenticated). Any other failure (backend down, timeout, malformed answer) is an
 * ERROR signal, which {@link BffSessionIntrospectionWebFilter} turns into a fail-closed 503.
 */
@FunctionalInterface
public interface BffSessionIntrospector {

    Mono<BffSessionIntrospection> introspect(String bffToken);
}

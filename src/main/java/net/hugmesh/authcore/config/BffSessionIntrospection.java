package net.hugmesh.authcore.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Objects;

/**
 * What admin-bff's {@code GET /bff/internal/session/introspect} says about an opaque
 * {@code bff_} session: the subset of its response a downstream service needs to build a Spring
 * Security {@code Authentication}. Unknown response fields are ignored, so the endpoint can grow
 * without breaking a consumer pinned to an older jar.
 *
 * <p>{@code status} is NOT defaulted to {@code "active"}: a response that omits it carries a
 * blank (unknown) status, which {@link BffSessionIntrospectionWebFilter} refuses. {@code roles}
 * defaults to empty and is copied defensively.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BffSessionIntrospection(
        String id,
        String provider,
        List<String> roles,
        boolean registrationComplete,
        String status,
        boolean mfaSatisfied) {

    public BffSessionIntrospection {
        if (id == null) id = "";
        if (provider == null) provider = "";
        roles = roles == null ? List.of() : List.copyOf(roles.stream().filter(Objects::nonNull).toList());
        if (status == null) status = "";
    }
}

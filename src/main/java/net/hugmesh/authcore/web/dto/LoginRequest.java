package net.hugmesh.authcore.web.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/login}. All fields optional at the bean-validation
 * level because the controller derives the provider/handle from whichever of
 * {@code email} / {@code username} is present (its existing flexible semantics):
 * {@code provider} defaults to {@code discord} when a {@code username} is given,
 * else {@code google}. The constraints only bound a PRESENT value:
 *
 * <ul>
 *   <li>{@code provider} — if supplied, must be {@code google} | {@code discord}
 *       (case-insensitive), matching the DB {@code ck_account_provider} CHECK;</li>
 *   <li>{@code email} / {@code username} — length-bounded.</li>
 * </ul>
 */
public record LoginRequest(
        @Pattern(regexp = "(?i)google|discord", message = "provider must be google or discord")
        String provider,

        @Size(max = 320, message = "email is too long")
        String email,

        @Size(max = 64, message = "username is too long")
        String username) {
}

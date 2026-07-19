package systems.hugmesh.authcore.casdoor;

/**
 * The token set returned by a Casdoor OIDC token-endpoint call (authorization-code exchange
 * or refresh). {@code refreshToken} and {@code idToken} may be null/blank depending on the
 * grant and the configured scopes; {@code expiresInSeconds} is the access-token lifetime the
 * authorization server reported (0 if absent — the caller then falls back to its configured
 * default). All values are SECRET: never log them, never return them to the browser — they
 * are custody-held server-side (see {@link BffCustodyCipher}).
 */
public record OidcTokens(
        String accessToken,
        String refreshToken,
        String idToken,
        long expiresInSeconds) {
}

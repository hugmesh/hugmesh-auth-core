package net.hugmesh.authcore.account;

import java.time.LocalDateTime;

/**
 * A caller-facing, immutable view of one {@code bff_session} row for the "list my active
 * sessions" read. Deliberately exposes ONLY the lifecycle-identity columns
 * ({@code token}, {@code accountId}, {@code createdAt}, {@code expiresAt}) and never the
 * sensitive custody/MFA internals of {@link BffSession} (the encrypted OIDC access/refresh
 * blobs, the MFA-satisfied flags). Downstream BFFs map this into their own user-safe DTO
 * (e.g. a fingerprint of {@code token} — never the raw token of OTHER sessions) before it
 * reaches a browser.
 *
 * <p>Returned by {@link AccountStore#sessionsForAccount(String)} so consumers do not depend
 * on the full @{@code Table} entity (which carries the band-180 custody columns). The
 * {@code accountId} is server-derived from the validated principal at the call site; this row
 * type carries no request-supplied identity.
 *
 * @param token     the opaque {@code bff_} session id (PK)
 * @param accountId the owning account id ({@code provider:handle}, e.g. {@code google:alice@x.com})
 * @param createdAt when the session was minted (no zone; matches the table's {@code timestamp})
 * @param expiresAt when the session expires (no zone; rows past this are reaped lazily)
 */
public record BffSessionRow(
        String token,
        String accountId,
        LocalDateTime createdAt,
        LocalDateTime expiresAt) {

    /** Project the full {@link BffSession} entity down to the caller-safe lifecycle columns. */
    static BffSessionRow of(BffSession s) {
        return new BffSessionRow(s.token(), s.accountId(), s.createdAt(), s.expiresAt());
    }
}

package net.hugmesh.authcore.casdoor;

import reactor.core.publisher.Mono;

/**
 * Verifies a presented SECOND FACTOR (TOTP code / WebAuthn assertion / recovery code)
 * for the calling Casdoor subject — the precondition for the A4 BFF-driven MFA challenge
 * dual-stamp. Pulled out as a SEAM so the {@link MfaChallengeService} orchestration is
 * unit-testable with a mocked verifier (the real verification talks to Casdoor's MFA
 * endpoints, whose exact 3.80 shape is version-specific and validated against the deployed
 * casdoor-all-in-one — exactly like {@link CasdoorAdminClient}'s add-user/update-role
 * payloads).
 *
 * <h3>Fail-closed</h3>
 * Any unknown factor, malformed credential, transport error, or null/blank input MUST
 * resolve to {@code false} (NEVER throw) so a verification that did not provably succeed
 * never stamps an MFA satisfaction.
 */
public interface MfaFactorVerifier {

    /** The supported second-factor kinds. {@code amr} is the value recorded on the
     *  {@code bff_session.amr} column for audit. */
    enum Factor {
        TOTP("otp"),
        WEBAUTHN("webauthn"),
        RECOVERY("recovery");

        private final String amr;

        Factor(String amr) {
            this.amr = amr;
        }

        /** The {@code amr} (authentication-method-reference) string recorded on the session. */
        public String amr() {
            return amr;
        }

        /** Parse a request {@code factor} string (case-insensitive); null for an unknown kind. */
        public static Factor parse(String s) {
            if (s == null) return null;
            String v = s.trim().toLowerCase();
            return switch (v) {
                case "totp", "otp" -> TOTP;
                case "webauthn", "u2f", "passkey" -> WEBAUTHN;
                case "recovery", "recovery-code", "backup" -> RECOVERY;
                default -> null;
            };
        }
    }

    /**
     * Verify {@code credential} as the given {@code factor} for the Casdoor user
     * identified by {@code subject}/{@code username}. {@code true} ONLY on a provably
     * successful verification; fail-closed ({@code false}) on everything else.
     *
     * @param subject    the Casdoor subject (JWT {@code sub}) — NEVER a client-supplied body field
     * @param username   the Casdoor username (for the org/username id the API keys on)
     * @param factor     the second-factor kind
     * @param credential the presented credential (TOTP code / WebAuthn assertion JSON / recovery code)
     */
    Mono<Boolean> verify(String subject, String username, Factor factor, String credential);
}

package systems.snapdragon.authcore.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/mfa/enroll/webauthn/verify} — the WebAuthn registration
 * (attestation) response JSON produced by {@code navigator.credentials.create()}.
 *
 * <p>SECURITY: carries ONLY the attestation; the owner is the authenticated subject and the
 * challenge is the server's pending challenge bound to the session (NEVER a body field), so a
 * caller cannot register a credential for another subject or replay a foreign challenge.
 */
public record WebAuthnAttestationRequest(
        @NotBlank(message = "attestation is required")
        @Size(max = 16384, message = "attestation is too large")
        String attestation) {
}

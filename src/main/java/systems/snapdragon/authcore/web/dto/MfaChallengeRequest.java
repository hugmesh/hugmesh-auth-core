package systems.snapdragon.authcore.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/mfa/challenge} (A4 BFF-driven MFA challenge dual-stamp).
 *
 * <p>SECURITY: the body carries ONLY the presented second factor — the {@code factor}
 * kind and the {@code credential} (TOTP code / WebAuthn assertion / recovery code). It
 * carries NO subject/username/session identifier: the acting identity is taken from the
 * validated JWT subject and the caller's opaque session token (cookie- or Bearer-borne)
 * server-side, so a caller can NEVER stamp MFA for another subject by forging a body field.
 */
public record MfaChallengeRequest(
        @NotBlank(message = "factor is required")
        @Size(max = 32, message = "factor is too long")
        String factor,

        @NotBlank(message = "credential is required")
        @Size(max = 4096, message = "credential is too long")
        String credential) {
}

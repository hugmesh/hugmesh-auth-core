package systems.snapdragon.authcore.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/mfa/enroll/totp/verify} — the TOTP passcode that finishes the
 * enrollment of the caller's in-progress (disabled) TOTP factor.
 *
 * <p>SECURITY: carries ONLY the passcode; the owner is the authenticated subject server-side
 * (NEVER a body field), so a caller can only finish THEIR OWN TOTP enrollment.
 */
public record MfaTotpVerifyRequest(
        @NotBlank(message = "passcode is required")
        @Size(min = 6, max = 8, message = "passcode must be a 6-digit TOTP code")
        String passcode) {
}

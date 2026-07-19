package systems.hugmesh.authcore.web.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Optional a11y-name body for {@code POST /bff/register/complete} (and the shared
 * shape the register/google + register/discord bodies carry inline): the login-ui's
 * {@code displayName} (the human-visible name, UTF-8) + {@code screenReaderName} (the
 * ASCII aria-label a screen reader announces). Both are forwarded to the user-bff
 * profile (best-effort) so the spoken name is recorded.
 *
 * <p>Both fields are OPTIONAL — a registration with neither still completes. The
 * constraints here only bound a PRESENT value; the user-bff is the source of truth
 * for the deep confusable / zero-width / default-ignorable checks on receipt
 * ({@code SafeDisplayName} / {@code SafeScreenReaderName} + the service-layer
 * re-check). The admin-bff enforces the cheap, load-bearing local rules:
 * length, and that {@code screenReaderName} is printable-ASCII only (U+0020..U+007E)
 * — the spoken name must be a clean ASCII string a homograph cannot be smuggled into.
 */
public record RegisterProfileRequest(
        @Size(max = 255, message = "displayName must be at most 255 chars")
        String displayName,

        @Size(max = 255, message = "screenReaderName must be at most 255 chars")
        @Pattern(regexp = "[\\x20-\\x7E]*",
                message = "screenReaderName must be printable ASCII only")
        String screenReaderName) {
}

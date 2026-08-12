package net.hugmesh.authcore.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/register/google}: the Gmail address the admin invited.
 * Required + a valid email shape so a malformed/blank address is a clean 400 before
 * the invite-gate lookup. The controller lowercases it (unchanged).
 *
 * <p>{@code displayName} (UTF-8, human-visible) + {@code screenReaderName} (ASCII
 * aria-label) are OPTIONAL and, when present, forwarded to the user-bff profile so
 * the a11y spoken name is recorded at registration. Same constraints + same
 * "user-bff is the source of truth for the deep checks" contract as
 * {@link RegisterProfileRequest}.
 */
public record RegisterEmailRequest(
        @NotBlank(message = "email is required")
        @Email(message = "email is not a valid address")
        @Size(max = 320, message = "email is too long")
        String email,

        @Size(max = 255, message = "displayName must be at most 255 chars")
        String displayName,

        @Size(max = 255, message = "screenReaderName must be at most 255 chars")
        @Pattern(regexp = "[\\x20-\\x7E]*",
                message = "screenReaderName must be printable ASCII only")
        String screenReaderName) {

    /** Back-compat constructor for the email-only body (no a11y names). */
    public RegisterEmailRequest(String email) {
        this(email, null, null);
    }
}

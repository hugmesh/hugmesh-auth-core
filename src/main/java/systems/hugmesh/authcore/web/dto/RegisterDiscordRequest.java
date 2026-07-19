package systems.hugmesh.authcore.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/register/discord}: the Discord username the admin
 * invited. Required + length-bounded so a blank/oversized handle is a clean 400
 * before the invite-gate lookup. The controller lowercases it (unchanged).
 *
 * <p>{@code displayName} (UTF-8, human-visible) + {@code screenReaderName} (ASCII
 * aria-label) are OPTIONAL and, when present, forwarded to the user-bff profile so
 * the a11y spoken name is recorded at registration. Same constraints + same
 * "user-bff is the source of truth for the deep checks" contract as
 * {@link RegisterProfileRequest}.
 */
public record RegisterDiscordRequest(
        @NotBlank(message = "username is required")
        @Size(max = 64, message = "username is too long")
        String username,

        @Size(max = 255, message = "displayName must be at most 255 chars")
        String displayName,

        @Size(max = 255, message = "screenReaderName must be at most 255 chars")
        @Pattern(regexp = "[\\x20-\\x7E]*",
                message = "screenReaderName must be printable ASCII only")
        String screenReaderName) {

    /** Back-compat constructor for the username-only body (no a11y names). */
    public RegisterDiscordRequest(String username) {
        this(username, null, null);
    }
}

package systems.snapdragon.authcore.casdoor;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.config.SessionCookieWebFilter;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.authcore.web.dto.MfaChallengeRequest;

import java.util.Map;

/**
 * A4 BFF-driven MFA challenge: {@code POST /bff/mfa/challenge}. On a provably-successful
 * second-factor verification it DUAL-STAMPS the caller's MFA satisfaction (authoritative
 * {@code bff_session} row + advisory Casdoor {@code mfa_satisfied_at} Property; see
 * {@link MfaChallengeService}).
 *
 * <h3>Subject from the JWT, NEVER a body field</h3>
 * The acting identity is the validated JWT subject ({@code jwt.getSubject()}) and the
 * caller's own opaque session token (resolved from the cookie-bridged {@code Authorization}
 * header) — the request body carries ONLY the presented factor + credential. A caller can
 * therefore never stamp MFA for a different subject.
 *
 * <h3>Ships dark (mirrors {@code DesktopStepUpController})</h3>
 * 503 while {@code app.casdoor.mfa.enabled=false} (the default) — the whole challenge leg
 * is inert until launch, and the 503 makes the dark posture explicit + testable. The
 * authenticated route gate ({@code anyExchange().authenticated()}) is NOT bypassed: an
 * anonymous caller never reaches here. When dark, NO factor is verified and NOTHING is
 * stamped.
 */
@RestController
@RequestMapping("/bff/mfa/challenge")
@Validated
public class MfaChallengeController {

    private static final Logger log = LoggerFactory.getLogger(MfaChallengeController.class);

    private final MfaChallengeService service;

    public MfaChallengeController(MfaChallengeService service) {
        this.service = service;
    }

    @Operation(summary = "Challenge", operationId = "mfaChallengeChallenge")
    @PostMapping
    public Mono<Map<String, Object>> challenge(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header,
            @Valid @RequestBody MfaChallengeRequest body) {
        // Ships dark: 503 before any verification/stamp while the leg is dark. Mirrors
        // DesktopStepUpController — the authenticated route gate still runs (an anonymous
        // caller is 401'd upstream), this only makes the dark posture explicit.
        if (!service.enabled()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "MFA challenge ships dark (app.casdoor.mfa.enabled=false) — no factor verified"));
        }
        // Subject + username come ONLY from the validated JWT (never a body field).
        String subject = subjectOf(auth);
        if (subject == null || subject.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String username = usernameOf(auth);
        // The caller's own opaque session token (cookie- or Bearer-borne) — the
        // authoritative stamp is keyed on THIS exact token (no cross-session bleed).
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(null, header);

        MfaFactorVerifier.Factor factor = MfaFactorVerifier.Factor.parse(body.factor());
        if (factor == null) {
            return Mono.error(ApiException.badRequest(
                    "unsupported factor — expected totp | webauthn | recovery"));
        }

        return service.challenge(subject, username, sessionToken, factor, body.credential())
                .map(satisfied -> {
                    if (!Boolean.TRUE.equals(satisfied)) {
                        // Verification failed OR no session row to stamp -> fail-closed 401.
                        throw ApiException.unauthorized("MFA factor not verified");
                    }
                    log.info("[mfa-challenge] MFA satisfied for subject (factor={})", factor);
                    return Map.<String, Object>of("mfaSatisfied", true);
                });
    }

    /** The validated-JWT subject ({@code sub}); falls back to the auth name for the
     *  opaque-session principal. Never a body field. */
    private static String subjectOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    /** The Casdoor username from the validated JWT {@code name} claim (the org/username id
     *  the Property write keys on). Null when no JWT is in hand (opaque-session-only run);
     *  the advisory Property write is then skipped (the authoritative session stamp still
     *  lands). */
    private static String usernameOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            Object name = jwt.getClaim("name");
            if (name != null && !name.toString().isBlank()) return name.toString();
        }
        return null;
    }
}

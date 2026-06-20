package systems.snapdragon.authcore.mfa;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.MfaStepUpService;
import systems.snapdragon.authcore.config.SessionCookieWebFilter;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.authcore.web.dto.MfaTotpVerifyRequest;
import systems.snapdragon.authcore.web.dto.WebAuthnAttestationRequest;

import java.util.List;
import java.util.Map;

/**
 * BFF-owned MFA ENROLLMENT surface (D6+D8 web path). The BFF owns the factor lifecycle —
 * generates the TOTP secret (AES-256-GCM at rest), runs its own WebAuthn ceremony, and
 * generates+hashes recovery codes — because Casdoor cannot verify a factor for a session-less
 * web user.
 *
 * <h3>owner == authenticated subject ALWAYS</h3>
 * The acting subject is the validated JWT subject ({@code jwt.getSubject()} / auth name),
 * NEVER a request-body field. Every endpoint operates ONLY on the caller's own factors.
 *
 * <h3>Ships dark (mirrors {@code MfaChallengeController})</h3>
 * EVERY endpoint 503s while {@code app.casdoor.mfa.enabled=false} (the default), so nothing
 * is reachable until enforcement is flipped later. The authenticated route gate is NOT
 * bypassed (an anonymous caller is 401'd upstream).
 *
 * <h3>Step-up on factor mutation</h3>
 * DELETE a factor and regenerate recovery codes are PRIVILEGED self-actions — they require a
 * FRESH MFA step-up ({@link MfaStepUpService#isFresh(String)} on the caller's session) so a
 * hijacked session cannot strip MFA. Enroll-first-factor is the bootstrap exception (no
 * factor to step-up against yet).
 */
@RestController
@RequestMapping("/bff/mfa")
@Validated
public class MfaEnrollmentController {

    private static final Logger log = LoggerFactory.getLogger(MfaEnrollmentController.class);

    private final MfaEnrollmentService service;
    private final MfaStepUpService stepUp;

    public MfaEnrollmentController(MfaEnrollmentService service, MfaStepUpService stepUp) {
        this.service = service;
        this.stepUp = stepUp;
    }

    // ── TOTP enroll ───────────────────────────────────────────────────────────────────

    /** Begin TOTP enroll — generates a CSPRNG secret (stored AES-GCM-encrypted, disabled) and
     *  returns the otpauth URI + the base32 secret for the QR (shown ONCE). */
    @Operation(summary = "Begin totp", operationId = "mfaEnrollmentBeginTotp")
    @PostMapping("/enroll/totp")
    public Mono<Map<String, Object>> beginTotp(Authentication auth) {
        return dark(auth).then(Mono.defer(() -> {
            String subject = subjectOf(auth);
            return service.beginTotpEnroll(subject, usernameOf(auth))
                    .map(r -> Map.<String, Object>of(
                            "factorId", r.factorId(),
                            "otpauthUri", r.otpauthUri(),
                            "secret", r.secret()));
        }));
    }

    /** Finish TOTP enroll — verify the passcode, enable the factor, and return a fresh set of
     *  recovery codes ONCE (store only hashes). No step-up: this is the bootstrap first factor. */
    @Operation(summary = "Verify totp", operationId = "mfaEnrollmentVerifyTotp")
    @PostMapping("/enroll/totp/verify")
    public Mono<Map<String, Object>> verifyTotp(Authentication auth,
                                                @Valid @RequestBody MfaTotpVerifyRequest body) {
        return dark(auth).then(Mono.defer(() ->
                service.verifyTotpEnroll(subjectOf(auth), body.passcode())
                        .map(codes -> Map.<String, Object>of(
                                "enabled", true,
                                "recoveryCodes", codes))));
    }

    // ── WebAuthn enroll ─────────────────────────────────────────────────────────────────

    /** Begin WebAuthn registration — issue a server challenge bound to the session (pending). */
    @Operation(summary = "Webauthn options", operationId = "mfaEnrollmentWebauthnOptions")
    @PostMapping("/enroll/webauthn/options")
    public Mono<Map<String, Object>> webauthnOptions(
            Authentication auth,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String cookie,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return dark(auth).then(Mono.defer(() -> {
            String sessionToken = SessionCookieWebFilter.bffTokenFrom(cookie, header);
            return service.beginWebAuthnEnroll(sessionToken).map(MfaEnrollmentController::optionsMap);
        }));
    }

    /** Finish WebAuthn registration — verify the attestation against the pending challenge +
     *  RP/origin, reject a dup, store the credential. */
    @Operation(summary = "Webauthn verify", operationId = "mfaEnrollmentWebauthnVerify")
    @PostMapping("/enroll/webauthn/verify")
    public Mono<Map<String, Object>> webauthnVerify(
            Authentication auth,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String cookie,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header,
            @Valid @RequestBody WebAuthnAttestationRequest body) {
        return dark(auth).then(Mono.defer(() -> {
            String sessionToken = SessionCookieWebFilter.bffTokenFrom(cookie, header);
            return service.verifyWebAuthnEnroll(subjectOf(auth), sessionToken, body.attestation())
                    .map(factorId -> Map.<String, Object>of("factorId", factorId, "enabled", true));
        }));
    }

    /** Issue an ASSERTION challenge (challenge-time) bound to the subject; consumed by the
     *  existing {@code POST /bff/mfa/challenge}. */
    @Operation(summary = "Webauthn assert options", operationId = "mfaEnrollmentWebauthnAssertOptions")
    @PostMapping("/assert/webauthn/options")
    public Mono<Map<String, Object>> webauthnAssertOptions(Authentication auth) {
        return dark(auth).then(Mono.defer(() ->
                service.beginWebAuthnAssertion(subjectOf(auth)).map(MfaEnrollmentController::optionsMap)));
    }

    // ── list / remove / recovery ─────────────────────────────────────────────────────────

    /** The caller's enrolled factors (type + enabled + createdAt; NEVER any secret). */
    @Operation(summary = "List factors", operationId = "mfaEnrollmentListFactors")
    @GetMapping("/factors")
    public Mono<Map<String, Object>> listFactors(Authentication auth) {
        return dark(auth).then(Mono.defer(() ->
                service.listFactors(subjectOf(auth))
                        .map(f -> Map.<String, Object>of(
                                "id", f.id(),
                                "type", f.type(),
                                "enabled", f.enabled(),
                                "createdAt", f.createdAt() == null ? "" : f.createdAt().toString()))
                        .collectList()
                        .map(list -> Map.<String, Object>of("factors", list))));
    }

    /** Remove a factor (owner-scoped). STEP-UP gated: a fresh MFA satisfaction is required so a
     *  hijacked session cannot strip MFA. */
    @Operation(summary = "Remove factor", operationId = "mfaEnrollmentRemoveFactor")
    @DeleteMapping("/factors/{id}")
    public Mono<Map<String, Object>> removeFactor(
            Authentication auth,
            @PathVariable String id,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String cookie,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return dark(auth).then(requireStepUp(cookie, header)).then(Mono.defer(() ->
                service.removeFactor(subjectOf(auth), id)
                        .map(removed -> Map.<String, Object>of("removed", removed))));
    }

    /** Regenerate recovery codes (invalidates the prior set); returns the new set ONCE.
     *  STEP-UP gated. */
    @Operation(summary = "Regenerate recovery", operationId = "mfaEnrollmentRegenerateRecovery")
    @PostMapping("/recovery/regenerate")
    public Mono<Map<String, Object>> regenerateRecovery(
            Authentication auth,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String cookie,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return dark(auth).then(requireStepUp(cookie, header)).then(Mono.defer(() ->
                service.regenerateRecoveryCodes(subjectOf(auth))
                        .map(codes -> Map.<String, Object>of("recoveryCodes", codes))));
    }

    // ── guards ────────────────────────────────────────────────────────────────────────

    /** Ships-dark + authenticated-subject precondition: 503 while MFA is dark, 401 with no
     *  subject. Mirrors {@code MfaChallengeController}. */
    private Mono<Void> dark(Authentication auth) {
        if (!stepUp.enabled()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "MFA enrollment ships dark (app.casdoor.mfa.enabled=false)"));
        }
        String subject = subjectOf(auth);
        if (subject == null || subject.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return Mono.empty();
    }

    /** Require a FRESH MFA step-up on the caller's session for a privileged factor mutation. */
    private Mono<Void> requireStepUp(String cookie, String header) {
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(cookie, header);
        return stepUp.isFresh(sessionToken).flatMap(fresh -> {
            if (!Boolean.TRUE.equals(fresh)) {
                return Mono.error(ApiException.forbidden(
                        "requires a fresh MFA step-up to mutate factors"));
            }
            // Single-use: consume the freshness so a second mutation needs a fresh challenge.
            return stepUp.consume(sessionToken);
        });
    }

    private static Map<String, Object> optionsMap(MfaEnrollmentService.WebAuthnOptions o) {
        return Map.of("challenge", o.challenge(), "rpId", o.rpId(), "rpName", o.rpName());
    }

    /** The validated-JWT subject ({@code sub}); falls back to the auth name. Never a body field. */
    private static String subjectOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    /** The Casdoor username (JWT {@code name}) for the otpauth account label; falls back to
     *  the subject. Never a body field. */
    private static String usernameOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            Object name = jwt.getClaim("name");
            if (name != null && !name.toString().isBlank()) {
                return name.toString();
            }
        }
        return subjectOf(auth);
    }
}

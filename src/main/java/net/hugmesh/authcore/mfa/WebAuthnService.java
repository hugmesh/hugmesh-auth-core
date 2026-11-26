package net.hugmesh.authcore.mfa;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * The BFF-OWNED WebAuthn ceremony (registration attestation + authentication assertion),
 * built on WebAuthn4J. Casdoor's WebAuthn is session-bound and cannot be driven on-behalf-of
 * a session-less web user, so the BFF runs its own ceremony: server-generated challenge
 * bound to the session, then verify the response against the RP ID + origin allowlist +
 * challenge, and (for assertion) the signature + sign-count monotonicity (clone detection).
 *
 * <p>This component is SYNCHRONOUS (WebAuthn4J is blocking); callers wrap it on Reactor's
 * boundedElastic at the reactive boundary. Every public method is FAIL-CLOSED: a malformed
 * response, a verification exception, or any unexpected error surfaces as a thrown
 * {@link WebAuthnException} the caller maps to {@code false}/4xx — never a silent pass.
 *
 * <h3>RP / origin config</h3>
 * {@code app.mfa.webauthn.rp-id} (the registrable domain, e.g. {@code hugmesh.net})
 * and {@code app.mfa.webauthn.origins} (the CSV origin allowlist, e.g.
 * {@code https://admin.hugmesh.net}). The challenge is generated server-side and the
 * caller binds it to the session (stored pending) — this service is stateless about the
 * pending challenge; the caller passes back the exact issued challenge to verify against.
 */
@Component
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    /**
     * Server-challenge size in bytes. The W3C floor is 16; we draw 32 so the challenge is a
     * full 256 bits and matches the digest width the assertion is signed over.
     */
    static final int CHALLENGE_BYTES = 32;

    /**
     * The challenge CSPRNG. {@link SecureRandom} is thread-safe, and the no-arg constructor
     * takes the platform's strong default (on Linux, a non-blocking kernel entropy source), so
     * a shared instance is both correct and free of the blocking risk {@code getInstanceStrong()}
     * would add on a freshly booted node.
     */
    private static final SecureRandom CHALLENGE_RNG = new SecureRandom();

    private final WebAuthnManager manager;
    private final ObjectConverter objectConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final String rpId;
    private final Set<Origin> origins;
    private final String rpName;

    public WebAuthnService(
            @Value("${app.mfa.webauthn.rp-id:localhost}") String rpId,
            @Value("${app.mfa.webauthn.origins:https://localhost}") String originsCsv,
            @Value("${app.mfa.totp.issuer:HugMesh}") String rpName) {
        // createNonStrictWebAuthnManager: no attestation-statement trust-anchor verification
        // (we accept self-attestation / none — second-factor enrollment, not device-trust).
        // The RP ID, origin, challenge, signature, and SIGN-COUNT checks are ALL still
        // enforced — those are the security-relevant checks for a 2FA ceremony.
        this.objectConverter = new ObjectConverter();
        this.manager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
        this.attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        this.rpId = (rpId == null || rpId.isBlank()) ? "localhost" : rpId.trim();
        this.rpName = (rpName == null || rpName.isBlank()) ? "HugMesh" : rpName.trim();
        this.origins = new HashSet<>();
        if (originsCsv != null) {
            for (String o : originsCsv.split(",")) {
                String t = o.trim();
                if (!t.isEmpty()) {
                    this.origins.add(new Origin(t));
                }
            }
        }
        if (this.origins.isEmpty()) {
            this.origins.add(new Origin("https://localhost"));
        }
    }

    /** The configured RP ID (the registrable domain) — surfaced in the options response. */
    public String rpId() {
        return rpId;
    }

    /** The configured RP display name (brand) — surfaced in the options response. */
    public String rpName() {
        return rpName;
    }

    /**
     * A fresh base64url-encoded server challenge the caller binds to the session:
     * {@value #CHALLENGE_BYTES} bytes drawn from a {@link SecureRandom}, i.e. a full
     * {@code CHALLENGE_BYTES * 8} bits of entropy.
     *
     * <p>NOT {@code new DefaultChallenge()}. webauthn4j's no-arg constructor is
     * {@code UUID.randomUUID()} packed into a 16-byte buffer, so it carries 122 usable bits —
     * RFC 4122 fixes the version nibble and the variant bits — and it draws from the UUID
     * generator rather than a challenge-sized CSPRNG. That clears the W3C "SHOULD be at least
     * 16 bytes" floor, so this is a hardening rather than a fix for a live hole, but it also
     * silently contradicted this javadoc, which claimed 32 bytes while the code produced 16.
     * {@code WebAuthnServiceTest} pins the size and the CSPRNG-vs-UUID distinction so the two
     * cannot drift apart again.
     */
    public String newChallengeBase64Url() {
        byte[] raw = new byte[CHALLENGE_BYTES];
        CHALLENGE_RNG.nextBytes(raw);
        return Base64UrlUtil.encodeToString(raw);
    }

    /**
     * Verify a REGISTRATION (attestation) response against the issued {@code challengeB64Url}.
     * Enforces RP ID, origin allowlist, and challenge match. On success returns the durable
     * {@link RegisteredCredential} the caller persists (credentialId base64url, the
     * AttestationObject CBOR base64, initial sign count). Throws {@link WebAuthnException} on
     * any failure (fail-closed).
     *
     * @param registrationResponseJson the navigator.credentials.create() response JSON
     * @param challengeB64Url          the EXACT server challenge issued for this session
     */
    public RegisteredCredential verifyRegistration(String registrationResponseJson,
                                                   String challengeB64Url) {
        try {
            Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeB64Url));
            ServerProperty serverProperty = new ServerProperty(origins, rpId, challenge, null);
            // userVerificationRequired=false (2FA: presence is enough), userPresenceRequired=true.
            RegistrationParameters params = new RegistrationParameters(serverProperty, null, false, true);
            RegistrationData data = manager.verifyRegistrationResponseJSON(registrationResponseJson, params);

            AttestationObject attestationObject = data.getAttestationObject();
            if (attestationObject == null
                    || attestationObject.getAuthenticatorData().getAttestedCredentialData() == null) {
                throw new WebAuthnException("no attested credential data");
            }
            byte[] credentialIdBytes = attestationObject.getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialId();
            long signCount = attestationObject.getAuthenticatorData().getSignCount();
            // Store the whole AttestationObject CBOR (carries the COSE public key + auth data)
            // so the assertion path can rebuild a CredentialRecord. base64 (standard).
            byte[] attestationCbor = attestationObjectConverter.convertToBytes(attestationObject);

            String transports = null;
            if (data.getTransports() != null && !data.getTransports().isEmpty()) {
                StringBuilder sb = new StringBuilder();
                data.getTransports().forEach(t -> {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(t.getValue());
                });
                transports = sb.toString();
            }
            return new RegisteredCredential(
                    Base64UrlUtil.encodeToString(credentialIdBytes),
                    java.util.Base64.getEncoder().encodeToString(attestationCbor),
                    signCount,
                    transports);
        } catch (WebAuthnException e) {
            throw e;
        } catch (Exception e) {
            log.debug("[webauthn] registration verify failed (fail-closed): {}", e.toString());
            throw new WebAuthnException("registration verification failed");
        }
    }

    /**
     * Verify an AUTHENTICATION (assertion) response against the issued {@code challengeB64Url}
     * and a stored credential. Enforces RP ID, origin, challenge, the SIGNATURE (against the
     * stored COSE key), and SIGN-COUNT monotonicity (clone detection: a stale/equal counter
     * with a non-zero stored count is rejected by WebAuthn4J's MaliciousCounterValueException).
     * On success returns the NEW sign count to persist. Throws {@link WebAuthnException} on any
     * failure (fail-closed).
     *
     * @param authenticationResponseJson the navigator.credentials.get() response JSON
     * @param challengeB64Url            the EXACT server challenge issued for this assertion
     * @param storedAttestationCborB64   the base64 AttestationObject CBOR persisted at registration
     * @param storedSignCount            the last-persisted sign count (the monotonic floor)
     */
    public long verifyAssertion(String authenticationResponseJson,
                                String challengeB64Url,
                                String storedAttestationCborB64,
                                long storedSignCount) {
        try {
            AttestationObject attestationObject = attestationObjectConverter.convert(
                    java.util.Base64.getDecoder().decode(storedAttestationCborB64));
            // Rebuild the CredentialRecord from the stored attestation (carries the COSE key
            // the signature verifies against). clientData/extensions are not needed for the
            // assertion signature check; pass nulls.
            CredentialRecord credentialRecord = new CredentialRecordImpl(
                    attestationObject, null, null, null);
            // Seed the record's counter with the stored floor so WebAuthn4J's sign-count
            // monotonicity check (MaliciousCounterValueException) fires on a clone/replay.
            credentialRecord.setCounter(storedSignCount);

            Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeB64Url));
            ServerProperty serverProperty = new ServerProperty(origins, rpId, challenge, null);
            AuthenticationParameters params = new AuthenticationParameters(
                    serverProperty, credentialRecord, null, false, true);

            AuthenticationData data = manager.verifyAuthenticationResponseJSON(
                    authenticationResponseJson, params);
            long newCount = data.getAuthenticatorData() == null ? storedSignCount
                    : data.getAuthenticatorData().getSignCount();
            return newCount;
        } catch (Exception e) {
            log.debug("[webauthn] assertion verify failed (fail-closed): {}", e.toString());
            throw new WebAuthnException("assertion verification failed");
        }
    }

    /** Parse a registration/assertion response JSON to its credentialId (base64url) WITHOUT
     *  verifying — used to look up the stored credential the assertion is against. Fail-closed
     *  null on any parse error. */
    public String credentialIdOfAssertion(String authenticationResponseJson) {
        try {
            // The assertion response carries the rawId / id (base64url) at the top level.
            com.fasterxml.jackson.databind.JsonNode node =
                    JSON.readTree(authenticationResponseJson);
            com.fasterxml.jackson.databind.JsonNode id = node.get("rawId");
            if (id == null || id.isNull()) {
                id = node.get("id");
            }
            return (id == null || id.isNull()) ? null : id.asText();
        } catch (Exception e) {
            return null;
        }
    }

    /** A plain Jackson mapper for the lightweight credentialId extraction (not the WebAuthn
     *  parse — that goes through WebAuthn4J's converters in the verify methods). */
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON =
            new com.fasterxml.jackson.databind.ObjectMapper();

    /** A verified, durable WebAuthn credential ready to persist. */
    public record RegisteredCredential(String credentialIdBase64Url,
                                       String attestationCborBase64,
                                       long signCount,
                                       String transports) {
    }

    /** Fail-closed marker for any WebAuthn ceremony failure (the caller maps to false/4xx). */
    public static class WebAuthnException extends RuntimeException {
        public WebAuthnException(String message) {
            super(message);
        }
    }
}

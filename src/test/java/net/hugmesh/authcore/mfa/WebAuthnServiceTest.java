package net.hugmesh.authcore.mfa;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The BFF-owned WebAuthn ceremony, exercised against a REAL software authenticator built in this
 * test out of webauthn4j-core + the plain JDK ({@link TestAuthenticator} below).
 *
 * <h3>Why there is a genuine positive path here</h3>
 * An earlier draft of this file asserted only negatives on the premise that a valid fixture needs
 * the separate {@code webauthn4j-test} artifact. That premise is wrong. {@code
 * WebAuthnManager.createNonStrictWebAuthnManager} accepts {@code fmt=none} attestation (no trust
 * anchor — deliberate: this is second-factor enrollment, not device attestation), so a
 * registration fixture needs no signature at all, and an ASSERTION fixture needs only a real
 * ES256 signature over {@code authenticatorData || SHA-256(clientDataJSON)} — which the JDK's
 * {@code SHA256withECDSA} produces from the same EC key pair the attestation object carries.
 * {@link TestAuthenticator} therefore plays the authenticator honestly rather than restating the
 * ceremony.
 *
 * <p>That matters because it is the only way to prove the checks FIRE rather than merely that
 * something threw: every negative below is the SAME genuine fixture with exactly ONE property
 * spoiled (origin / RP-ID / challenge / signature / signing key / sign count), so a rejection can
 * only be attributed to the check being tested. The previous negatives-only version of this file
 * could not do that, and three of its assertion tests were vacuous as a result (they passed an
 * unparseable stored credential, so the assertion payload under test was never read — see the
 * comment on {@link #verifyAssertion_garbagePayloads_allThrowWebAuthnException}).
 */
class WebAuthnServiceTest {

    private static final String RP_ID = "hugmesh.systems";
    private static final String ORIGIN = "https://admin.hugmesh.systems";

    private final WebAuthnService service = new WebAuthnService(RP_ID, ORIGIN, "HugMesh");

    /** A syntactically valid, freshly generated challenge (so a rejection is never "bad b64"). */
    private final String challenge = service.newChallengeBase64Url();

    private final TestAuthenticator authenticator = new TestAuthenticator();

    // ── RP identity comes from config ────────────────────────────────────────────────────

    @Test
    void rpIdAndRpName_comeFromConfig() {
        assertThat(service.rpId()).isEqualTo(RP_ID);
        assertThat(service.rpName()).isEqualTo("HugMesh");

        WebAuthnService other = new WebAuthnService("tenant.example.org",
                "https://ui.tenant.example.org", "Tenant Brand");
        assertThat(other.rpId()).isEqualTo("tenant.example.org");
        assertThat(other.rpName()).isEqualTo("Tenant Brand");
    }

    @Test
    void rpIdAndRpName_blankOrNullConfig_fallBackToTheDocumentedDefaults() {
        assertThat(new WebAuthnService(null, null, null).rpId()).isEqualTo("localhost");
        assertThat(new WebAuthnService("   ", null, "  ").rpId()).isEqualTo("localhost");
        assertThat(new WebAuthnService(null, null, null).rpName()).isEqualTo("HugMesh");
    }

    @Test
    void rpIdAndRpName_areTrimmed() {
        assertThat(new WebAuthnService("  hugmesh.systems  ", null, "  Brand  ").rpId())
                .isEqualTo("hugmesh.systems");
        assertThat(new WebAuthnService("  hugmesh.systems  ", null, "  Brand  ").rpName())
                .isEqualTo("Brand");
    }

    @Test
    void malformedConfiguredOrigin_failsFastAtConstruction() {
        // A typo'd origin must not silently drop out of the allowlist — WebAuthn4J's Origin
        // parser rejects it and the bean fails to build.
        assertThatThrownBy(() -> new WebAuthnService(RP_ID, "not a url", "HugMesh"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── the ServerProperty (RP-ID + origin allowlist) is config-derived AND enforced ──────
    //
    // These are BEHAVIOURAL proofs. WebAuthnService builds
    //     new ServerProperty(origins, rpId, challenge, null)
    // at WebAuthnService.java:114 (registration) and :183 (assertion). Rather than reflect over
    // the private fields, each test below feeds the ceremony a genuine fixture that differs from
    // the accepted one in exactly one ServerProperty input.

    @Test
    void registration_acceptsAGenuineAttestation_forTheConfiguredRpIdAndOrigin() {
        WebAuthnService.RegisteredCredential cred = service.verifyRegistration(
                authenticator.registrationResponseJson(challenge, ORIGIN, RP_ID, 0L), challenge);

        assertThat(cred.credentialIdBase64Url()).isEqualTo(authenticator.credentialIdBase64Url());
        assertThat(cred.signCount()).isZero();
        // The persisted blob is the one the assertion path later rebuilds a CredentialRecord from.
        assertThat(cred.attestationCborBase64()).isNotBlank();
        assertThat(Base64.getDecoder().decode(cred.attestationCborBase64())).isNotEmpty();
    }

    @Test
    void registration_rejects_anOriginThatIsNotInTheConfiguredAllowlist() {
        // Identical fixture, one property spoiled: the client claims a different origin.
        String hostile = authenticator.registrationResponseJson(
                challenge, "https://evil.example.com", RP_ID, 0L);
        assertThatThrownBy(() -> service.verifyRegistration(hostile, challenge))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void registration_rejects_anRpIdHashForADifferentRelyingParty() {
        String wrongRp = authenticator.registrationResponseJson(
                challenge, ORIGIN, "evil.example.com", 0L);
        assertThatThrownBy(() -> service.verifyRegistration(wrongRp, challenge))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void registration_rejects_aResponseBoundToADifferentChallenge() {
        String otherChallenge = service.newChallengeBase64Url();
        String forOtherChallenge =
                authenticator.registrationResponseJson(otherChallenge, ORIGIN, RP_ID, 0L);
        assertThatThrownBy(() -> service.verifyRegistration(forOtherChallenge, challenge))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void originAllowlist_everyConfiguredCsvEntry_isAccepted_andNothingElseIs() {
        WebAuthnService multi = new WebAuthnService(RP_ID,
                " https://admin.hugmesh.systems , https://app.hugmesh.systems ,, ", "HugMesh");
        String c = multi.newChallengeBase64Url();

        // Both configured origins work (proves the CSV split + trim reach the ServerProperty)...
        assertThat(multi.verifyRegistration(
                authenticator.registrationResponseJson(c, "https://admin.hugmesh.systems", RP_ID, 0L), c))
                .isNotNull();
        assertThat(multi.verifyRegistration(
                authenticator.registrationResponseJson(c, "https://app.hugmesh.systems", RP_ID, 0L), c))
                .isNotNull();
        // ...and a third one does not.
        assertThatThrownBy(() -> multi.verifyRegistration(
                authenticator.registrationResponseJson(c, "https://other.hugmesh.systems", RP_ID, 0L), c))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
        // Scheme is part of the origin: plain http on an allowlisted host is NOT the same origin.
        assertThatThrownBy(() -> multi.verifyRegistration(
                authenticator.registrationResponseJson(c, "http://admin.hugmesh.systems", RP_ID, 0L), c))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void originAllowlist_unconfigured_degradesToLocalhostOnly_neverToAnyOrigin() {
        // The important half: an unconfigured deployment gets a SINGLE local origin, NOT a
        // wildcard. A silent "any origin" would be the dangerous failure mode.
        for (String unset : new String[]{null, "  ,  "}) {
            WebAuthnService dflt = new WebAuthnService(RP_ID, unset, "HugMesh");
            String c = dflt.newChallengeBase64Url();
            assertThat(dflt.verifyRegistration(
                    authenticator.registrationResponseJson(c, "https://localhost", RP_ID, 0L), c))
                    .as("origins=%s must still accept the localhost default", unset)
                    .isNotNull();
            assertThatThrownBy(() -> dflt.verifyRegistration(
                    authenticator.registrationResponseJson(c, ORIGIN, RP_ID, 0L), c))
                    .as("origins=%s must NOT accept an unconfigured production origin", unset)
                    .isInstanceOf(WebAuthnService.WebAuthnException.class);
        }
    }

    // ── challenge generation ─────────────────────────────────────────────────────────────

    @Test
    void newChallenge_meetsTheWebAuthn16ByteFloor_andIsBase64Url() {
        String c = service.newChallengeBase64Url();
        // W3C WebAuthn: the challenge SHOULD be at least 16 bytes. This assertion survives a
        // future widening of the challenge, unlike the exact-size tripwire below.
        assertThat(Base64UrlUtil.decode(c)).hasSizeGreaterThanOrEqualTo(16);
        // base64url alphabet only — no '+', '/' or '=' padding (it goes into JSON/URLs).
        assertThat(c).matches("[A-Za-z0-9_-]+");
    }

    @Test
    void newChallenge_isExactly32SecureRandomBytes_notTheUuidDerived16() {
        // Pins the CHALLENGE_BYTES draw. The predecessor of this test recorded the opposite
        // state: the javadoc claimed 32 bytes while the code called `new DefaultChallenge()`,
        // whose no-arg form in webauthn4j 0.31.7 is
        //     ByteBuffer.allocate(16).putLong(uuid.getMostSignificantBits())
        //                            .putLong(uuid.getLeastSignificantBits()).array()
        // — 16 bytes carrying a random UUID, so 122 usable bits with 6 FIXED by RFC 4122.
        // That cleared the W3C 16-byte floor, so the switch is a hardening, not a fix for a
        // live hole; this assertion is what stops a revert to the UUID form going unnoticed.
        byte[] raw = Base64UrlUtil.decode(service.newChallengeBase64Url());
        assertThat(raw).hasSize(WebAuthnService.CHALLENGE_BYTES);
        assertThat(WebAuthnService.CHALLENGE_BYTES)
                .as("32 bytes = 256 bits; also keeps the W3C >=16 floor true by construction")
                .isEqualTo(32);
    }

    @Test
    void newChallenge_carriesNoRfc4122StructureAcrossManyDraws() {
        // Size alone would still pass if someone concatenated two UUIDs to reach 32 bytes, which
        // would reintroduce the fixed version/variant bits. A UUID-derived challenge holds
        // raw[6]&0xf0 == 0x40 and raw[8]&0xc0 == 0x80 on EVERY draw; a CSPRNG hits each only
        // ~1/16 and ~1/4 of the time. Over 256 draws, "always" and "sometimes" are not
        // confusable: the false-failure probability here is (15/16 * 3/4)^-… vanishing, while a
        // UUID-shaped source fails on the very first draw.
        int versionNibbleMatches = 0;
        int variantBitsMatches = 0;
        for (int i = 0; i < 256; i++) {
            byte[] raw = Base64UrlUtil.decode(service.newChallengeBase64Url());
            if ((raw[6] & 0xf0) == 0x40) versionNibbleMatches++;
            if ((raw[8] & 0xc0) == 0x80) variantBitsMatches++;
        }
        assertThat(versionNibbleMatches)
                .as("RFC 4122 v4 version nibble present in every draw => UUID-derived, not CSPRNG")
                .isLessThan(256);
        assertThat(variantBitsMatches)
                .as("RFC 4122 variant bits present in every draw => UUID-derived, not CSPRNG")
                .isLessThan(256);
    }

    @Test
    void newChallenge_isFreshPerCall() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 512; i++) {
            assertThat(seen.add(service.newChallengeBase64Url()))
                    .as("challenge #%d repeated a previous value", i).isTrue();
        }
        // 512 distinct values: a fixed or low-entropy challenge cannot pass this.
        assertThat(seen).hasSize(512);
    }

    @Test
    void newChallenge_isTheValueTheCeremonyActuallyVerifiesAgainst() {
        // Ties challenge GENERATION to challenge ENFORCEMENT: a fixture built for the challenge
        // this service issued verifies, and one built for a second issued challenge does not.
        String a = service.newChallengeBase64Url();
        String b = service.newChallengeBase64Url();
        assertThat(service.verifyRegistration(
                authenticator.registrationResponseJson(a, ORIGIN, RP_ID, 0L), a)).isNotNull();
        assertThatThrownBy(() -> service.verifyRegistration(
                authenticator.registrationResponseJson(b, ORIGIN, RP_ID, 0L), a))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    // ── registration: fail-closed on anything that is not a real attestation ─────────────

    @Test
    void verifyRegistration_garbagePayloads_allThrowWebAuthnException() {
        for (String bogus : new String[]{
                "",
                "   ",
                "not json at all",
                "{}",
                "[]",
                "null",
                "{\"id\":\"abc\"}",
                // Right SHAPE, nonsense contents — the dangerous near-miss.
                "{\"id\":\"abc\",\"rawId\":\"abc\",\"type\":\"public-key\",\"response\":"
                        + "{\"clientDataJSON\":\"eyJmb28iOiJiYXIifQ\","
                        + "\"attestationObject\":\"AAAA\"}}",
                // A structurally plausible clientDataJSON for a DIFFERENT challenge/origin.
                "{\"id\":\"abc\",\"rawId\":\"abc\",\"type\":\"public-key\",\"response\":"
                        + "{\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdl"
                        + "IjoiQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXZpbC5leGFtcGxlLmNvbSJ9\","
                        + "\"attestationObject\":\"o2NmbXRkbm9uZQ\"}}",
        }) {
            assertThatThrownBy(() -> service.verifyRegistration(bogus, challenge))
                    .as("payload %s must be rejected", bogus)
                    .isInstanceOf(WebAuthnService.WebAuthnException.class);
        }
    }

    @Test
    void verifyRegistration_nullPayload_throwsWebAuthnException_notNpe() {
        assertThatThrownBy(() -> service.verifyRegistration(null, challenge))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyRegistration_malformedChallenge_throwsWebAuthnException_notIllegalArgument() {
        // Base64UrlUtil.decode throws IllegalArgumentException on a bad challenge; the service
        // MUST wrap it so no non-fail-closed exception type escapes to the caller. Note the
        // payload here is a GENUINE attestation — the only defect is the challenge argument.
        String good = authenticator.registrationResponseJson(challenge, ORIGIN, RP_ID, 0L);
        assertThatThrownBy(() -> service.verifyRegistration(good, "!!! not base64url !!!"))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
        assertThatThrownBy(() -> service.verifyRegistration(good, null))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyRegistration_failureMessage_leaksNoInternals() {
        assertThatThrownBy(() -> service.verifyRegistration("not json", challenge))
                .isInstanceOf(WebAuthnService.WebAuthnException.class)
                .hasMessage("registration verification failed");
    }

    // ── assertion: verified against a REAL stored credential ─────────────────────────────

    @Test
    void verifyAssertion_acceptsAGenuineSignedAssertion_andReturnsTheNewSignCount() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        long newCount = service.verifyAssertion(
                authenticator.assertionResponseJson(challenge, ORIGIN, RP_ID, 5L), challenge,
                stored, 0L);
        assertThat(newCount).isEqualTo(5L);
    }

    @Test
    void verifyAssertion_rejects_aTamperedSignature() {
        // THE signature check. Same authenticator, same everything — one flipped signature byte.
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String tampered = authenticator.assertionResponseJsonWithTamperedSignature(
                challenge, ORIGIN, RP_ID, 5L);
        assertThatThrownBy(() -> service.verifyAssertion(tampered, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_rejects_anAssertionSignedByADifferentKeyPair() {
        // A perfectly well-formed assertion from ANOTHER authenticator must not verify against
        // this credential's stored COSE public key.
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        TestAuthenticator impostor = new TestAuthenticator(authenticator.credentialIdBytes());
        String otherKeysAssertion = impostor.assertionResponseJson(challenge, ORIGIN, RP_ID, 5L);
        assertThatThrownBy(() -> service.verifyAssertion(otherKeysAssertion, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_rejects_anAssertionBoundToADifferentChallenge() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String otherChallenge = service.newChallengeBase64Url();
        String forOtherChallenge =
                authenticator.assertionResponseJson(otherChallenge, ORIGIN, RP_ID, 5L);
        assertThatThrownBy(() -> service.verifyAssertion(forOtherChallenge, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_rejects_anOriginThatIsNotInTheConfiguredAllowlist() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String hostile = authenticator.assertionResponseJson(
                challenge, "https://evil.example.com", RP_ID, 5L);
        assertThatThrownBy(() -> service.verifyAssertion(hostile, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_rejects_anRpIdHashForADifferentRelyingParty() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String wrongRp = authenticator.assertionResponseJson(
                challenge, ORIGIN, "evil.example.com", 5L);
        assertThatThrownBy(() -> service.verifyAssertion(wrongRp, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_signCountMonotonicity_isTheCloneDetector() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        // Advancing past the stored floor is fine...
        assertThat(service.verifyAssertion(
                authenticator.assertionResponseJson(challenge, ORIGIN, RP_ID, 6L),
                challenge, stored, 5L)).isEqualTo(6L);
        // ...but an EQUAL counter against a non-zero floor is the classic cloned-authenticator
        // signal and WebAuthn4J must reject it (MaliciousCounterValueException)...
        String c2 = service.newChallengeBase64Url();
        assertThatThrownBy(() -> service.verifyAssertion(
                authenticator.assertionResponseJson(c2, ORIGIN, RP_ID, 5L), c2, stored, 5L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
        // ...as must a counter that has gone BACKWARDS.
        String c3 = service.newChallengeBase64Url();
        assertThatThrownBy(() -> service.verifyAssertion(
                authenticator.assertionResponseJson(c3, ORIGIN, RP_ID, 4L), c3, stored, 5L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_garbagePayloads_allThrowWebAuthnException() {
        // The stored credential is a REAL, parseable attestation blob. That is the whole point:
        // an earlier version of this test passed base64({1,2,3,4}) here, which made
        // attestationObjectConverter.convert() throw on the FIRST line of verifyAssertion
        // (WebAuthnService.java:171) so the payload under test was never read — every case
        // "passed" for the same irrelevant reason. With a genuine blob, the rejection can only
        // come from the payload.
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        for (String bogus : new String[]{
                "",
                "   ",
                "not json at all",
                "{}",
                "[]",
                "null",
                "{\"id\":\"abc\"}",
                // Right SHAPE, nonsense contents.
                "{\"id\":\"abc\",\"rawId\":\"abc\",\"type\":\"public-key\",\"response\":"
                        + "{\"clientDataJSON\":\"eyJmb28iOiJiYXIifQ\","
                        + "\"authenticatorData\":\"AAAA\",\"signature\":\"AAAA\"}}",
        }) {
            assertThatThrownBy(() -> service.verifyAssertion(bogus, challenge, stored, 0L))
                    .as("payload %s must be rejected", bogus)
                    .isInstanceOf(WebAuthnService.WebAuthnException.class);
        }
    }

    @Test
    void verifyAssertion_nullPayload_throwsWebAuthnException_notNpe() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        assertThatThrownBy(() -> service.verifyAssertion(null, challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_unreadableStoredCredential_throwsWebAuthnException() {
        // A distinct leg from the one above: the PAYLOAD is a genuine signed assertion and only
        // the persisted credential blob is corrupt. Must still fail closed.
        String good = authenticator.assertionResponseJson(challenge, ORIGIN, RP_ID, 5L);
        for (String badStored : new String[]{
                "not-base64!!!", null, "",
                Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4}),
        }) {
            assertThatThrownBy(() -> service.verifyAssertion(good, challenge, badStored, 0L))
                    .as("stored blob %s must fail closed", badStored)
                    .isInstanceOf(WebAuthnService.WebAuthnException.class);
        }
    }

    @Test
    void verifyAssertion_malformedChallenge_throwsWebAuthnException_notIllegalArgument() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String good = authenticator.assertionResponseJson(challenge, ORIGIN, RP_ID, 5L);
        assertThatThrownBy(() -> service.verifyAssertion(good, "!!! not base64url !!!", stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
        assertThatThrownBy(() -> service.verifyAssertion(good, null, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    @Test
    void verifyAssertion_failureMessage_leaksNoInternals() {
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        assertThatThrownBy(() -> service.verifyAssertion("not json", challenge, stored, 0L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class)
                .hasMessage("assertion verification failed");
    }

    @Test
    void verifyAssertion_neverReturnsTheStoredCountAsASilentPass() {
        // Regression guard on the SHAPE of failure: a rejected assertion must THROW, so the
        // caller (BffStoredMfaFactorVerifier) can never read "verification failed" as "counter
        // unchanged, all good" — which is exactly what returning storedSignCount would look like.
        String stored = authenticator.storedAttestationCborBase64(RP_ID, 0L);
        String tampered = authenticator.assertionResponseJsonWithTamperedSignature(
                challenge, ORIGIN, RP_ID, 42L);
        assertThatThrownBy(() -> service.verifyAssertion(tampered, challenge, stored, 42L))
                .isInstanceOf(WebAuthnService.WebAuthnException.class);
    }

    // ── credentialId extraction (pre-verification lookup only) ───────────────────────────

    @Test
    void credentialIdOfAssertion_prefersRawId_thenId() {
        assertThat(service.credentialIdOfAssertion(
                "{\"rawId\":\"RAW\",\"id\":\"ID\"}")).isEqualTo("RAW");
        assertThat(service.credentialIdOfAssertion("{\"id\":\"ID\"}")).isEqualTo("ID");
        assertThat(service.credentialIdOfAssertion(
                "{\"rawId\":null,\"id\":\"ID\"}")).isEqualTo("ID");
    }

    @Test
    void credentialIdOfAssertion_onAGenuineAssertion_isTheRegisteredCredentialId() {
        // Ties the lightweight lookup key to the value registration actually persists — if these
        // two disagreed, the verifier's credential lookup would never find the row.
        String registered = service.verifyRegistration(
                authenticator.registrationResponseJson(challenge, ORIGIN, RP_ID, 0L), challenge)
                .credentialIdBase64Url();
        String assertion = authenticator.assertionResponseJson(challenge, ORIGIN, RP_ID, 5L);
        assertThat(service.credentialIdOfAssertion(assertion)).isEqualTo(registered);
    }

    @Test
    void credentialIdOfAssertion_failsClosedNull_onAnythingUnusable() {
        assertThat(service.credentialIdOfAssertion("{}")).isNull();
        assertThat(service.credentialIdOfAssertion("{\"rawId\":null,\"id\":null}")).isNull();
        assertThat(service.credentialIdOfAssertion("not json")).isNull();
        assertThat(service.credentialIdOfAssertion("")).isNull();
        assertThat(service.credentialIdOfAssertion(null)).isNull();
    }

    // ── a real software authenticator ────────────────────────────────────────────────────

    /**
     * A minimal but GENUINE software authenticator: a secp256r1 key pair, an {@code fmt=none}
     * attestation object carrying its COSE public key, and real {@code SHA256withECDSA}
     * signatures over {@code authenticatorData || SHA-256(clientDataJSON)} as the WebAuthn spec
     * requires. Nothing here reimplements a verification step — it only produces the artefacts a
     * browser + security key would.
     */
    private static final class TestAuthenticator {

        private static final ObjectConverter OC = new ObjectConverter();
        private static final AttestationObjectConverter ATTESTATION = new AttestationObjectConverter(OC);
        private static final AuthenticatorDataConverter AUTH_DATA = new AuthenticatorDataConverter(OC);

        private final KeyPair keyPair;
        private final byte[] credentialId;

        TestAuthenticator() {
            this(deterministicCredentialId());
        }

        /** A second authenticator reusing another's credentialId — the impostor case. */
        TestAuthenticator(byte[] credentialId) {
            this.credentialId = credentialId.clone();
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                this.keyPair = g.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static byte[] deterministicCredentialId() {
            byte[] id = new byte[32];
            for (int i = 0; i < id.length; i++) {
                id[i] = (byte) (i * 7 + 1);
            }
            return id;
        }

        byte[] credentialIdBytes() {
            return credentialId.clone();
        }

        String credentialIdBase64Url() {
            return Base64UrlUtil.encodeToString(credentialId);
        }

        /** The attestation object a registration would persist, as the service stores it (base64). */
        String storedAttestationCborBase64(String rpIdForHash, long signCount) {
            return Base64.getEncoder().encodeToString(attestationCbor(rpIdForHash, signCount));
        }

        private byte[] attestationCbor(String rpIdForHash, long signCount) {
            try {
                EC2COSEKey cose = EC2COSEKey.create((ECPublicKey) keyPair.getPublic(),
                        COSEAlgorithmIdentifier.ES256);
                AttestedCredentialData attested =
                        new AttestedCredentialData(AAGUID.ZERO, credentialId, cose);
                // UP: user present. AT: attested credential data included (required at register).
                byte flags = (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_AT);
                AuthenticatorData<RegistrationExtensionAuthenticatorOutput> data =
                        new AuthenticatorData<>(sha256(rpIdForHash.getBytes(StandardCharsets.UTF_8)),
                                flags, signCount, attested,
                                new AuthenticationExtensionsAuthenticatorOutputs<>());
                return ATTESTATION.convertToBytes(
                        new AttestationObject(data, new NoneAttestationStatement()));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        String registrationResponseJson(String challengeB64Url, String origin, String rpIdForHash,
                                        long signCount) {
            String clientData = clientDataJson("webauthn.create", challengeB64Url, origin);
            return "{\"id\":\"" + credentialIdBase64Url()
                    + "\",\"rawId\":\"" + credentialIdBase64Url()
                    + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                    + b64Url(clientData)
                    + "\",\"attestationObject\":\""
                    + Base64UrlUtil.encodeToString(attestationCbor(rpIdForHash, signCount))
                    + "\"},\"clientExtensionResults\":{}}";
        }

        String assertionResponseJson(String challengeB64Url, String origin, String rpIdForHash,
                                     long signCount) {
            return assertion(challengeB64Url, origin, rpIdForHash, signCount, false);
        }

        String assertionResponseJsonWithTamperedSignature(String challengeB64Url, String origin,
                                                          String rpIdForHash, long signCount) {
            return assertion(challengeB64Url, origin, rpIdForHash, signCount, true);
        }

        private String assertion(String challengeB64Url, String origin, String rpIdForHash,
                                 long signCount, boolean tamperSignature) {
            try {
                // Assertion authenticator data carries NO attested credential data (no AT flag).
                AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> data =
                        new AuthenticatorData<>(sha256(rpIdForHash.getBytes(StandardCharsets.UTF_8)),
                                AuthenticatorData.BIT_UP, signCount,
                                new AuthenticationExtensionsAuthenticatorOutputs<>());
                byte[] authDataBytes = AUTH_DATA.convert(data);
                byte[] clientDataBytes = clientDataJson("webauthn.get", challengeB64Url, origin)
                        .getBytes(StandardCharsets.UTF_8);

                // The spec's signed payload: authenticatorData || SHA-256(clientDataJSON).
                byte[] clientDataHash = sha256(clientDataBytes);
                byte[] signedOver = new byte[authDataBytes.length + clientDataHash.length];
                System.arraycopy(authDataBytes, 0, signedOver, 0, authDataBytes.length);
                System.arraycopy(clientDataHash, 0, signedOver, authDataBytes.length,
                        clientDataHash.length);

                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(keyPair.getPrivate());
                signer.update(signedOver);
                byte[] signature = signer.sign();
                if (tamperSignature) {
                    // Flip a bit in the middle of the DER-encoded r/s — still parseable DER, but
                    // no longer a valid signature over this payload.
                    signature[signature.length - 2] ^= 0x01;
                }

                return "{\"id\":\"" + credentialIdBase64Url()
                        + "\",\"rawId\":\"" + credentialIdBase64Url()
                        + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                        + Base64UrlUtil.encodeToString(clientDataBytes)
                        + "\",\"authenticatorData\":\"" + Base64UrlUtil.encodeToString(authDataBytes)
                        + "\",\"signature\":\"" + Base64UrlUtil.encodeToString(signature)
                        + "\",\"userHandle\":null},\"clientExtensionResults\":{}}";
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String clientDataJson(String type, String challengeB64Url, String origin) {
            return "{\"type\":\"" + type + "\",\"challenge\":\"" + challengeB64Url
                    + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
        }

        private static String b64Url(String s) {
            return Base64UrlUtil.encodeToString(s.getBytes(StandardCharsets.UTF_8));
        }

        private static byte[] sha256(byte[] input) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(input);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}

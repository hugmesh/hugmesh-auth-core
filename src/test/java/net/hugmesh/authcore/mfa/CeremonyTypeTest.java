package net.hugmesh.authcore.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CeremonyType} is a CODE-SIDE LENS over the {@code webauthn_challenge.ceremony_type}
 * String column: it MUST emit / parse byte-identical lowercase wire tokens so the persistence
 * edge (and the put/consume signatures, which stay String) are unaffected. Mirrors the
 * federation #46 {@code ScopeKind} round-trip test: {@code value()} == the exact legacy
 * constant, {@code fromWire} is the inverse, Jackson serializes the same bytes, and unknown /
 * null is fail-soft null.
 */
class CeremonyTypeTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void value_isByteIdenticalToLegacyConstants() {
        // The legacy public constants on WebAuthnChallengeStore now delegate to the enum —
        // assert the canonical tokens are exactly the historical lowercase strings the column holds.
        assertThat(CeremonyType.REGISTER.value()).isEqualTo("register");
        assertThat(CeremonyType.ASSERT.value()).isEqualTo("assert");
        assertThat(WebAuthnChallengeStore.PURPOSE_REGISTER).isEqualTo("register");
        assertThat(WebAuthnChallengeStore.PURPOSE_ASSERT).isEqualTo("assert");
        // and the constant IS the enum value (single source of truth)
        assertThat(WebAuthnChallengeStore.PURPOSE_REGISTER).isEqualTo(CeremonyType.REGISTER.value());
        assertThat(WebAuthnChallengeStore.PURPOSE_ASSERT).isEqualTo(CeremonyType.ASSERT.value());
    }

    @Test
    void fromWire_isInverseOfValue() {
        for (CeremonyType c : CeremonyType.values()) {
            assertThat(CeremonyType.fromWire(c.value())).isEqualTo(c);
        }
        assertThat(CeremonyType.fromWire(WebAuthnChallengeStore.PURPOSE_REGISTER))
                .isEqualTo(CeremonyType.REGISTER);
        assertThat(CeremonyType.fromWire(WebAuthnChallengeStore.PURPOSE_ASSERT))
                .isEqualTo(CeremonyType.ASSERT);
    }

    @Test
    void fromWire_isFailSoftOnNullAndUnknown() {
        assertThat(CeremonyType.fromWire(null)).isNull();
        assertThat(CeremonyType.fromWire("")).isNull();
        assertThat(CeremonyType.fromWire("REGISTER")).isNull(); // case-sensitive on canonical token
        assertThat(CeremonyType.fromWire("authenticate")).isNull();
    }

    @Test
    void jacksonRoundTrip_emitsAndParsesIdenticalWireTokens() throws Exception {
        assertThat(json.writeValueAsString(CeremonyType.REGISTER)).isEqualTo("\"register\"");
        assertThat(json.writeValueAsString(CeremonyType.ASSERT)).isEqualTo("\"assert\"");
        assertThat(json.readValue("\"register\"", CeremonyType.class)).isEqualTo(CeremonyType.REGISTER);
        assertThat(json.readValue("\"assert\"", CeremonyType.class)).isEqualTo(CeremonyType.ASSERT);
    }
}

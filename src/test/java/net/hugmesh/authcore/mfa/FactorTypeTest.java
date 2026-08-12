package net.hugmesh.authcore.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link FactorType} is a CODE-SIDE LENS over the {@code mfa_factor.type} String column: it MUST
 * emit / parse byte-identical wire tokens so the persistence edge and any cross-repo reader are
 * unaffected by the enum's introduction. Mirrors the federation #46 {@code ScopeKind} round-trip
 * test: prove {@code value()} == the exact legacy String constant, {@code fromWire} is the
 * inverse, the Jackson serialization is the same bytes, and unknown / null is fail-soft null.
 */
class FactorTypeTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void value_isByteIdenticalToLegacyConstants() {
        // The legacy public constants on MfaFactorRow now delegate to the enum — assert the
        // canonical tokens are exactly the historical strings the DB column has always held.
        assertThat(FactorType.TOTP.value()).isEqualTo("TOTP");
        assertThat(FactorType.WEBAUTHN.value()).isEqualTo("WEBAUTHN");
        assertThat(MfaFactorRow.TYPE_TOTP).isEqualTo("TOTP");
        assertThat(MfaFactorRow.TYPE_WEBAUTHN).isEqualTo("WEBAUTHN");
        // and the constant IS the enum value (single source of truth)
        assertThat(MfaFactorRow.TYPE_TOTP).isEqualTo(FactorType.TOTP.value());
        assertThat(MfaFactorRow.TYPE_WEBAUTHN).isEqualTo(FactorType.WEBAUTHN.value());
    }

    @Test
    void fromWire_isInverseOfValue() {
        for (FactorType t : FactorType.values()) {
            assertThat(FactorType.fromWire(t.value())).isEqualTo(t);
        }
        // parses the exact bytes the column / legacy constants store
        assertThat(FactorType.fromWire(MfaFactorRow.TYPE_TOTP)).isEqualTo(FactorType.TOTP);
        assertThat(FactorType.fromWire(MfaFactorRow.TYPE_WEBAUTHN)).isEqualTo(FactorType.WEBAUTHN);
    }

    @Test
    void fromWire_isFailSoftOnNullAndUnknown() {
        assertThat(FactorType.fromWire(null)).isNull();
        assertThat(FactorType.fromWire("")).isNull();
        assertThat(FactorType.fromWire("totp")).isNull();      // case-sensitive on canonical token
        assertThat(FactorType.fromWire("RECOVERY")).isNull();  // not a row type
        assertThat(FactorType.fromWire("nonsense")).isNull();
    }

    @Test
    void jacksonRoundTrip_emitsAndParsesIdenticalWireTokens() throws Exception {
        // @JsonValue serializes to the bare quoted wire token (the same bytes the column holds),
        // and @JsonCreator parses it back — no behavior/format drift vs. a plain String.
        assertThat(json.writeValueAsString(FactorType.TOTP)).isEqualTo("\"TOTP\"");
        assertThat(json.writeValueAsString(FactorType.WEBAUTHN)).isEqualTo("\"WEBAUTHN\"");
        assertThat(json.readValue("\"TOTP\"", FactorType.class)).isEqualTo(FactorType.TOTP);
        assertThat(json.readValue("\"WEBAUTHN\"", FactorType.class)).isEqualTo(FactorType.WEBAUTHN);
    }
}

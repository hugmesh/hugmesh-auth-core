package net.hugmesh.authcore.mfa;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed {@code webauthn_challenge.ceremony_type} vocabulary — a CODE-SIDE LENS over the
 * {@code @Column("ceremony_type")} String stored on {@link WebAuthnChallengeRow}. A pending
 * WebAuthn challenge is issued for exactly one of two ceremonies: a credential REGISTRATION
 * (the {@code .../options} -> {@code .../verify} enroll pair) or an ASSERTION (the
 * challenge-time login/step-up assertion). Both tokens are written and read entirely inside
 * this repo (no external source).
 *
 * <p>Mirrors the proven federation #46 {@code ScopeKind} idiom: a {@link JsonValue}
 * {@link #value()} + a null-tolerant {@link JsonCreator} {@link #fromWire(String)} that emit /
 * parse the IDENTICAL lowercase wire tokens, while the persistence edge stays String. The
 * {@code @Column("ceremony_type") String} on {@link WebAuthnChallengeRow}, the
 * {@link WebAuthnChallengeStore#put put}/{@link WebAuthnChallengeStore#consume consume}
 * signatures, and the {@link WebAuthnChallengeR2dbcRepository} query parameters are ALL
 * UNCHANGED — R2DBC mapping is byte-identical. The legacy
 * {@link WebAuthnChallengeStore#PURPOSE_REGISTER}/{@link WebAuthnChallengeStore#PURPOSE_ASSERT}
 * constants now delegate to {@link #REGISTER}{@code .value()} / {@link #ASSERT}{@code .value()}
 * so every existing call site keeps emitting the exact same {@code register}/{@code assert}
 * bytes.
 */
public enum CeremonyType {

    /** Credential REGISTRATION ceremony (enroll). Wire/DB token: {@code register}. */
    REGISTER("register"),
    /** Credential ASSERTION ceremony (login / step-up). Wire/DB token: {@code assert}. */
    ASSERT("assert");

    private final String wire;

    CeremonyType(String wire) {
        this.wire = wire;
    }

    /** The exact lowercase wire/DB token (e.g. {@code register}) stored in
     *  {@code webauthn_challenge.ceremony_type} — the same String the legacy constants emitted,
     *  so the DB column + any cross-repo reader see identical bytes. */
    @JsonValue
    public String value() {
        return wire;
    }

    /** Parse a stored/wire token; returns {@code null} for {@code null} or any unrecognised
     *  token (fail-soft — never an exception). Case-sensitive on the canonical lowercase token,
     *  matching the exact bytes the column holds. */
    @JsonCreator
    public static CeremonyType fromWire(String token) {
        if (token == null) {
            return null;
        }
        for (CeremonyType c : values()) {
            if (c.wire.equals(token)) {
                return c;
            }
        }
        return null;
    }
}

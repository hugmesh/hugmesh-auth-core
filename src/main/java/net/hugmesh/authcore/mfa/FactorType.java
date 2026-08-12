package net.hugmesh.authcore.mfa;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed {@code mfa_factor.type} discriminator vocabulary — a CODE-SIDE LENS over the
 * {@code @Column("type")} String stored on {@link MfaFactorRow}. This is a genuinely closed,
 * app-OWNED set: a {@code mfa_factor} row only ever stores {@code TOTP} or {@code WEBAUTHN},
 * both written and read entirely inside this repo (no external/federation source).
 *
 * <p>Mirrors the proven federation #46 {@code ScopeKind} idiom: a {@link JsonValue}
 * {@link #value()} + a null-tolerant {@link JsonCreator} {@link #fromWire(String)} that emit /
 * parse the IDENTICAL wire tokens, while the persistence edge stays String. The
 * {@code @Column("type") String type} on {@link MfaFactorRow} and the
 * {@link MfaFactorR2dbcRepository#findByOwnerSubjectAndType repository} signatures are
 * UNCHANGED — R2DBC mapping is byte-identical. The legacy
 * {@link MfaFactorRow#TYPE_TOTP}/{@link MfaFactorRow#TYPE_WEBAUTHN} constants now delegate to
 * {@link #TOTP}{@code .value()} / {@link #WEBAUTHN}{@code .value()} so every existing call site
 * keeps emitting the exact same {@code TOTP}/{@code WEBAUTHN} bytes.
 *
 * <p>NOTE: this is a DIFFERENT axis from the sibling {@code MfaFactorVerifier.Factor} enum —
 * that one additionally carries {@code RECOVERY} and {@code amr} wire tokens ({@code otp}/
 * {@code webauthn}/{@code recovery}) for the {@code bff_session.amr} audit column. The row
 * {@code type} column only ever stores {@code TOTP}|{@code WEBAUTHN}, so the two are NOT merged.
 */
public enum FactorType {

    /** Time-based one-time-password (TOTP) factor. Wire/DB token: {@code TOTP}. */
    TOTP("TOTP"),
    /** WebAuthn (passkey / security-key) factor. Wire/DB token: {@code WEBAUTHN}. */
    WEBAUTHN("WEBAUTHN");

    private final String wire;

    FactorType(String wire) {
        this.wire = wire;
    }

    /** The exact wire/DB token (e.g. {@code TOTP}) stored in {@code mfa_factor.type} — the
     *  same String the legacy constants emitted, so cross-repo readers see identical bytes. */
    @JsonValue
    public String value() {
        return wire;
    }

    /** Parse a stored/wire token (e.g. from {@code MfaFactorRow.type()}); returns {@code null}
     *  for {@code null} or any unrecognised token (fail-soft — a row with an unexpected type is
     *  simply not matched, never an exception). Case-sensitive on the canonical uppercase token,
     *  matching the exact bytes the row column holds. */
    @JsonCreator
    public static FactorType fromWire(String token) {
        if (token == null) {
            return null;
        }
        for (FactorType t : values()) {
            if (t.wire.equals(token)) {
                return t;
            }
        }
        return null;
    }
}

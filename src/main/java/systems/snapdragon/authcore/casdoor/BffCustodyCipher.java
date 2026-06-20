package systems.snapdragon.authcore.casdoor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES-256-GCM authenticated encryption for the OIDC tokens the BFF custody-holds AT REST in
 * {@code bff_session} (the {@code access_token} and {@code refresh_token} columns added by the
 * admin-bff band-180 custody migration). The browser only ever holds the opaque {@code bff_}
 * session id; the real Casdoor JWT + refresh_token live server-side, encrypted with a random
 * 96-bit nonce per value, stored as {@code base64(nonce || ciphertext || GCM-tag)}.
 *
 * <p>This is the sibling of {@link systems.snapdragon.authcore.mfa.MfaSecretCipher} (same
 * AES-256-GCM construction, same key-derivation rules) but keyed independently from
 * {@code app.bff.custody-key} so the token-at-rest key and the TOTP-secret key are separate
 * key-management concerns and can be rotated/scoped independently.
 *
 * <h3>Key source</h3>
 * The 256-bit data key comes from {@code app.bff.custody-key} (fed by ESO/Vault) — NEVER
 * hardcoded, committed, or logged. A base64/base64url 32-byte value is used verbatim; any
 * other passphrase is folded to 32 bytes via SHA-256.
 *
 * <h3>Dark posture</h3>
 * When no key is configured the cipher is INERT: {@link #isAvailable()} is false. The OIDC
 * custody flow is already dark behind {@code app.bff.oidc.enabled}; an
 * {@code InternalSurfaceBootGuard}-style guard fails fast if OIDC is enabled without a custody
 * key, so there is never a plaintext-token fallback. {@link #decrypt} fails closed (returns
 * null) on any tamper/wrong-key/malformed input.
 */
@Component
public class BffCustodyCipher {

    private static final Logger log = LoggerFactory.getLogger(BffCustodyCipher.class);

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;   // 96-bit GCM nonce (NIST-recommended).
    private static final int TAG_BITS = 128;     // 128-bit GCM auth tag.
    private static final int KEY_BYTES = 32;     // AES-256.

    private final SecureRandom random = new SecureRandom();
    private final byte[] key; // null when unconfigured -> cipher inert.

    public BffCustodyCipher(@Value("${app.bff.custody-key:}") String configuredKey) {
        this.key = deriveKey(configuredKey);
        if (this.key == null) {
            log.info("[bff-custody] no app.bff.custody-key configured — OIDC token custody is INERT "
                    + "until a key is provisioned (ships-dark posture)");
        }
    }

    /** Whether a usable encryption key is configured (OIDC custody requires this). */
    public boolean isAvailable() {
        return key != null;
    }

    /**
     * Encrypt a held token ({@code access_token} or {@code refresh_token}) and return
     * {@code base64(nonce || ciphertext || tag)} with a fresh random 96-bit nonce per call.
     *
     * @throws IllegalStateException if no key is configured (caller must check
     *                               {@link #isAvailable()} first)
     */
    public String encrypt(String plaintext) {
        if (key == null) {
            throw new IllegalStateException("BFF custody key not configured");
        }
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ct, 0, out, nonce.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("BFF custody-token encryption failed", e);
        }
    }

    /**
     * Decrypt a {@code base64(nonce || ciphertext || tag)} blob back to the held token.
     * Returns null on any error (tampered blob, wrong key, malformed input, no key) — the
     * exchange path treats a null token as "cannot resolve" and fails closed (the gateway
     * rejects the {@code bff_} rather than forwarding an unauthenticated request).
     */
    public String decrypt(String stored) {
        if (key == null || stored == null || stored.isBlank()) {
            return null;
        }
        try {
            byte[] blob = Base64.getDecoder().decode(stored);
            if (blob.length <= NONCE_BYTES) {
                return null;
            }
            byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(blob, NONCE_BYTES, blob.length);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.debug("[bff-custody] decrypt failed (fail-closed)");
            return null;
        }
    }

    /** Fold the configured key material to a 32-byte AES key, or null when unconfigured. */
    private static byte[] deriveKey(String configured) {
        if (configured == null || configured.isBlank()) {
            return null;
        }
        String v = configured.trim();
        byte[] decoded = tryDecode(v);
        if (decoded != null && decoded.length == KEY_BYTES) {
            return decoded;
        }
        try {
            return MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable (JVM fault)", e);
        }
    }

    private static byte[] tryDecode(String v) {
        try {
            return Base64.getDecoder().decode(v);
        } catch (RuntimeException ignore) {
            try {
                return Base64.getUrlDecoder().decode(v);
            } catch (RuntimeException ignore2) {
                return null;
            }
        }
    }
}

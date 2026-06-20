package systems.snapdragon.authcore.mfa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Recovery (backup) codes: a SET of high-entropy one-time codes shown ONCE at enroll, of
 * which only a salted KEYED HASH is ever stored. A code is HMAC-SHA256'd under a server-side
 * key ({@code app.mfa.factor-key}, the same secret-store key the cipher uses — a keyed hash,
 * not a bare digest, so the stored hashes are useless without the server key even if the
 * table leaks). Verification is a constant-time compare of the keyed hash; a match consumes
 * the code one-time. Regenerate invalidates the prior set.
 *
 * <p>HMAC-SHA256 (keyed) is chosen over Argon2/bcrypt because (a) the inputs are
 * HIGH-ENTROPY CSPRNG codes (≈100 bits), not low-entropy human passwords, so a slow
 * password KDF buys nothing, and (b) Argon2 needs BouncyCastle in a way that the GraalVM
 * native image path avoids (cf. {@code BackupCrypto}'s same reasoning). The server-key HMAC
 * gives the table-leak resistance the requirement asks for.
 */
@Component
public class RecoveryCodeService {

    /** How many recovery codes a set contains. */
    public static final int CODE_COUNT = 10;
    /** 10 CSPRNG bytes = 80 bits, encoded as exactly 16 base32 chars (16 * 5 = 80). */
    private static final int CODE_BYTES = 10;
    /** Length of the unformatted code (RFC-4648 base32 of {@link #CODE_BYTES}, no padding). */
    private static final int CODE_CHARS = (CODE_BYTES * 8) / 5; // 80 / 5 = 16
    private static final String HMAC_ALGO = "HmacSHA256";
    /** RFC-4648 base32 alphabet (A-Z2-7); index = 5-bit group value, so the map is bijective. */
    private static final char[] B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private final SecureRandom random = new SecureRandom();
    private final byte[] hmacKey; // null when unconfigured -> service inert.

    public RecoveryCodeService(@Value("${app.mfa.factor-key:}") String configuredKey) {
        this.hmacKey = deriveKey(configuredKey);
    }

    /** Whether a server key is configured (recovery-code generation requires it). */
    public boolean isAvailable() {
        return hmacKey != null;
    }

    /**
     * Generate a fresh SET of {@value #CODE_COUNT} plaintext recovery codes (formatted
     * {@code XXXX-XXXX-XXXX-XXXX}). Shown ONCE to the user at enroll/regenerate; the caller
     * stores ONLY {@link #hash(String)} of each. NEVER logged.
     */
    public List<String> generateCodes() {
        List<String> codes = new ArrayList<>(CODE_COUNT);
        for (int i = 0; i < CODE_COUNT; i++) {
            codes.add(formatCode(randomCode()));
        }
        return codes;
    }

    /**
     * The base64 HMAC-SHA256 keyed hash of {@code code} (case/format-normalised). Stored at
     * generate time; re-derived + constant-time compared at verify time. Returns null when
     * unconfigured.
     */
    public String hash(String code) {
        if (hmacKey == null || code == null) {
            return null;
        }
        String normalised = normalise(code);
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(hmacKey, HMAC_ALGO));
            byte[] h = mac.doFinal(normalised.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(h);
        } catch (Exception e) {
            throw new IllegalStateException("recovery-code HMAC failed", e);
        }
    }

    /** Constant-time check that {@code code} hashes to {@code storedHash}. */
    public boolean matches(String code, String storedHash) {
        if (hmacKey == null || code == null || storedHash == null) {
            return false;
        }
        String actual = hash(code);
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }

    /** Normalise a presented code (strip separators, upper-case) for a format-tolerant compare. */
    static String normalise(String code) {
        return code.replace("-", "").replace(" ", "").trim().toUpperCase();
    }

    /**
     * One code = {@value #CODE_CHARS} chars of full-entropy RFC-4648 base32 over
     * {@value #CODE_BYTES} fresh CSPRNG bytes (80 bits of real entropy). Each output char is one
     * DISTINCT 5-bit group of the input bit-stream (no overlapping windows, no {@code % 32}
     * modulo bias), so nominal and effective entropy are equal.
     */
    private String randomCode() {
        byte[] raw = new byte[CODE_BYTES];
        random.nextBytes(raw);
        StringBuilder sb = new StringBuilder(CODE_CHARS);
        int buffer = 0;      // accumulates input bits, MSB-first
        int bitsInBuffer = 0;
        for (byte b : raw) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5;
                int group = (buffer >>> bitsInBuffer) & 0x1f; // 0..31, distinct bits, bijective
                sb.append(B32[group]);
            }
        }
        // CODE_BYTES is a multiple of 5 bits -> no leftover bits and no padding.
        return sb.toString();
    }

    private static String formatCode(String s) {
        return s.substring(0, 4) + "-" + s.substring(4, 8) + "-"
                + s.substring(8, 12) + "-" + s.substring(12, 16);
    }

    private static byte[] deriveKey(String configured) {
        if (configured == null || configured.isBlank()) {
            return null;
        }
        try {
            // Domain-separate from the AES key by hashing with a label so the recovery HMAC
            // key is not byte-identical to the cipher key even though both derive from the
            // same secret-store value.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("mfa-recovery-hmac:".getBytes(StandardCharsets.UTF_8));
            return md.digest(configured.trim().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable (JVM fault)", e);
        }
    }
}

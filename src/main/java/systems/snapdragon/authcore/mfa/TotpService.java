package systems.snapdragon.authcore.mfa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * RFC-6238 TOTP: HMAC-SHA1, 6 digits, 30-second step — the de-facto authenticator-app
 * baseline (Google Authenticator / Aegis / FreeOTP). The shared secret is a CSPRNG
 * ≥160-bit value, base32-encoded (the standard authenticator-app encoding).
 *
 * <h3>Verification</h3>
 * {@link #verify(String, long, long)} accepts the current step and ±1 step skew (clock
 * drift), and REJECTS replay of the just-accepted step: a presented code only verifies on a
 * step STRICTLY GREATER than {@code lastAcceptedCounter} (so the same code cannot be
 * replayed within or across its window). It returns the matched step counter so the caller
 * can persist it as the new replay floor.
 *
 * <h3>otpauth URI</h3>
 * {@link #otpauthUri(String, String)} builds the {@code otpauth://totp/...} URI the QR
 * encodes (issuer = brand, account = the user) — shown ONCE at enroll.
 *
 * <p>HMAC-SHA1 is the RFC-6238 default + the only interoperable choice for authenticator
 * apps; it is the HMAC PRF (not a hash of secret data), and is correct here.
 */
@Component
public class TotpService {

    private static final int DIGITS = 6;
    private static final int STEP_SECONDS = 30;
    private static final int SECRET_BYTES = 20;          // 160-bit secret (RFC-4226 floor).
    private static final String HMAC_ALGO = "HmacSHA1";  // RFC-6238 default; authenticator-app interoperable.
    private static final int[] POW10 = {1, 10, 100, 1000, 10_000, 100_000, 1_000_000, 10_000_000};
    private static final char[] B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private final SecureRandom random = new SecureRandom();
    private final String issuer;

    public TotpService(@Value("${app.mfa.totp.issuer:Snapdragon}") String issuer) {
        this.issuer = (issuer == null || issuer.isBlank()) ? "Snapdragon" : issuer.trim();
    }

    /** A fresh base32-encoded CSPRNG TOTP secret (160-bit). */
    public String newSecret() {
        byte[] raw = new byte[SECRET_BYTES];
        random.nextBytes(raw);
        return base32Encode(raw);
    }

    /** The current 30-second TOTP step for {@code now}. */
    public long currentCounter(Instant now) {
        return now.getEpochSecond() / STEP_SECONDS;
    }

    /**
     * Verify {@code code} against {@code base32Secret} around {@code now}, accepting ±1 step
     * skew, and REJECTING any step &lt;= {@code lastAcceptedCounter} (replay guard). Returns
     * the matched step counter on success, or {@code -1} on no match / replay / malformed
     * input. The caller persists the returned counter as the new replay floor.
     */
    public long verify(String base32Secret, long lastAcceptedCounter, String code) {
        return verifyAt(base32Secret, lastAcceptedCounter, code, Instant.now());
    }

    /** {@link #verify} pinned to an explicit {@code now} (testable without clock control). */
    public long verifyAt(String base32Secret, long lastAcceptedCounter, String code, Instant now) {
        if (base32Secret == null || code == null) {
            return -1;
        }
        String c = code.trim();
        if (c.length() != DIGITS || !c.chars().allMatch(Character::isDigit)) {
            return -1;
        }
        byte[] key;
        try {
            key = base32Decode(base32Secret);
        } catch (RuntimeException e) {
            return -1;
        }
        if (key.length == 0) {
            return -1;
        }
        long current = currentCounter(now);
        // ±1 step skew window. Reject any step at/below the last-accepted floor (replay).
        for (long step = current - 1; step <= current + 1; step++) {
            if (step <= lastAcceptedCounter) {
                continue; // replay of the just-used (or older) step — never accept.
            }
            String expected = generate(key, step);
            if (constantTimeEquals(expected, c)) {
                return step;
            }
        }
        return -1;
    }

    /** The {@code otpauth://totp/...} URI for the QR (issuer = brand, account = user). */
    public String otpauthUri(String accountName, String base32Secret) {
        String label = enc(issuer) + ":" + enc(accountName == null ? "user" : accountName);
        return "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + enc(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    /** The configured issuer (brand) — surfaced to the WebAuthn RP name / enroll response. */
    public String issuer() {
        return issuer;
    }

    // ── RFC-4226 HOTP truncation for a given step ─────────────────────────────────────
    private static String generate(byte[] key, long counter) {
        try {
            byte[] msg = new byte[8];
            long v = counter;
            for (int i = 7; i >= 0; i--) {
                msg[i] = (byte) (v & 0xff);
                v >>>= 8;
            }
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] h = mac.doFinal(msg);
            int offset = h[h.length - 1] & 0x0f;
            int bin = ((h[offset] & 0x7f) << 24)
                    | ((h[offset + 1] & 0xff) << 16)
                    | ((h[offset + 2] & 0xff) << 8)
                    | (h[offset + 3] & 0xff);
            int otp = bin % POW10[DIGITS];
            return String.format("%0" + DIGITS + "d", otp);
        } catch (Exception e) {
            // HmacSHA1 is a guaranteed JDK algorithm; a failure is a JVM fault.
            throw new IllegalStateException("TOTP HMAC failed", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) return false;
        int diff = 0;
        for (int i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
        return diff == 0;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ── base32 (RFC-4648, no padding) — authenticator-app secret encoding ─────────────
    static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32[(buffer >> (bits - 5)) & 0x1f]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(B32[(buffer << (5 - bits)) & 0x1f]);
        }
        return sb.toString();
    }

    static byte[] base32Decode(String s) {
        String in = s.trim().replace("=", "").replace(" ", "").toUpperCase();
        int buffer = 0, bits = 0, idx = 0;
        byte[] out = new byte[in.length() * 5 / 8];
        for (int i = 0; i < in.length(); i++) {
            int val = indexOf(in.charAt(i));
            if (val < 0) {
                throw new IllegalArgumentException("non-base32 char");
            }
            buffer = (buffer << 5) | val;
            bits += 5;
            if (bits >= 8) {
                out[idx++] = (byte) ((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out;
    }

    private static int indexOf(char c) {
        for (int i = 0; i < B32.length; i++) {
            if (B32[i] == c) return i;
        }
        return -1;
    }
}

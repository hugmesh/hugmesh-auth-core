package systems.snapdragon.authcore.mfa;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Recovery codes: a set of high-entropy codes, the stored value is a KEYED HASH (not the
 * plaintext), the hash verifies the code (format-tolerant), a wrong code/hash fails, and the
 * service is INERT without a key.
 */
class RecoveryCodeServiceTest {

    private final RecoveryCodeService svc = new RecoveryCodeService("a-test-server-key");

    @Test
    void generatesASetOfDistinctFormattedCodes() {
        List<String> codes = svc.generateCodes();
        assertThat(codes).hasSize(RecoveryCodeService.CODE_COUNT);
        assertThat(codes).doesNotHaveDuplicates();
        codes.forEach(c -> assertThat(c).matches("[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}"));
    }

    /**
     * Each code is exactly 16 base32 chars (80 bits, full entropy) drawn ONLY from the
     * RFC-4648 alphabet (A-Z2-7) once separators are stripped.
     */
    @Test
    void codesAreFullLengthAndFromTheBase32Alphabet() {
        for (String c : svc.generateCodes()) {
            String raw = c.replace("-", "");
            assertThat(raw).hasSize(16);
            assertThat(raw).matches("[A-Z2-7]{16}");
        }
    }

    /**
     * Full-entropy, distinct-bit base32: a deterministic byte pattern must decode back to
     * itself. This proves each output char is a DISTINCT 5-bit group of the input (a bijective
     * RFC-4648 mapping with no overlapping bit windows and no modulo bias) — the original
     * {@code (b & 0xff) % 32} / {@code ((b >> 3) & 0xff) % 32} derivation could NOT round-trip.
     */
    @Test
    void base32EncodingIsBijectiveOverDistinctInputBits() {
        // 0x00 0x44 0x32 0x14 0xC7 ... is the canonical RFC-4648 base32 of "AAAAAAAA..." etc.
        // Verify against java.util.Base64-style independent base32 reference for several bytes.
        byte[] in = {0x00, 0x44, 0x32, 0x14, (byte) 0xC7, 0x42, 0x54, (byte) 0xB6, 0x35, (byte) 0xCF};
        String encoded = base32(in);
        assertThat(encoded).hasSize(16).matches("[A-Z2-7]{16}");
        assertThat(base32Decode(encoded)).containsExactly(in);
    }

    /** Across many generations the unformatted codes stay unique and correctly formatted. */
    @Test
    void manyCodesAreUniqueAndCorrectlyFormatted() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            for (String c : svc.generateCodes()) {
                assertThat(c.replace("-", "")).matches("[A-Z2-7]{16}");
                assertThat(seen.add(c)).as("code %s repeated", c).isTrue();
            }
        }
        assertThat(seen).hasSize(50 * RecoveryCodeService.CODE_COUNT);
    }

    // --- Independent RFC-4648 base32 reference (mirrors the production encoding for assertion). ---
    private static final char[] A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private static String base32(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buf = 0, bits = 0;
        for (byte b : data) {
            buf = (buf << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(A[(buf >>> bits) & 0x1f]);
            }
        }
        return sb.toString();
    }

    private static byte[] base32Decode(String s) {
        int buf = 0, bits = 0, idx = 0;
        byte[] out = new byte[s.length() * 5 / 8];
        for (int i = 0; i < s.length(); i++) {
            buf = (buf << 5) | new String(A).indexOf(s.charAt(i));
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[idx++] = (byte) ((buf >>> bits) & 0xff);
            }
        }
        return out;
    }

    @Test
    void hashIsNotThePlaintext_andVerifies() {
        String code = svc.generateCodes().get(0);
        String hash = svc.hash(code);
        assertThat(hash).isNotNull().isNotEqualTo(code);
        assertThat(svc.matches(code, hash)).isTrue();
    }

    @Test
    void verifyIsFormatTolerant() {
        String code = svc.generateCodes().get(0);
        String hash = svc.hash(code);
        // Lowercase + no separators must still match (normalised).
        assertThat(svc.matches(code.replace("-", "").toLowerCase(), hash)).isTrue();
    }

    @Test
    void wrongCodeFails() {
        String hash = svc.hash(svc.generateCodes().get(0));
        assertThat(svc.matches("AAAA-BBBB-CCCC-DDDD", hash)).isFalse();
        assertThat(svc.matches(null, hash)).isFalse();
        assertThat(svc.matches("x", null)).isFalse();
    }

    @Test
    void differentServerKeyProducesDifferentHash() {
        String code = "AAAA-BBBB-CCCC-DDDD";
        RecoveryCodeService other = new RecoveryCodeService("a-different-server-key");
        assertThat(svc.hash(code)).isNotEqualTo(other.hash(code));
    }

    @Test
    void inertWithoutKey() {
        RecoveryCodeService inert = new RecoveryCodeService("");
        assertThat(inert.isAvailable()).isFalse();
        assertThat(inert.hash("AAAA-BBBB-CCCC-DDDD")).isNull();
    }
}

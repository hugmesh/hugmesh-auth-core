package systems.snapdragon.authcore.mfa;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC-6238 TOTP correctness + the SECURITY-relevant behaviours: ±1 step skew, REPLAY
 * rejection (a step at/below the last-accepted floor never verifies), and otpauth URI shape.
 */
class TotpServiceTest {

    private final TotpService totp = new TotpService("Snapdragon");

    /** Reproduce the RFC-4226 HOTP truncation independently so the test does not just mirror
     *  the impl: generate the code for a step from the same secret and assert it verifies. */
    private static String codeFor(String base32Secret, long step) {
        try {
            byte[] key = TotpService.base32Decode(base32Secret);
            byte[] msg = new byte[8];
            long v = step;
            for (int i = 7; i >= 0; i--) { msg[i] = (byte) (v & 0xff); v >>>= 8; }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(msg);
            int off = h[h.length - 1] & 0x0f;
            int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16)
                    | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void newSecret_isBase32_andDecodes() {
        String s = totp.newSecret();
        assertThat(s).matches("[A-Z2-7]+");
        assertThat(TotpService.base32Decode(s)).hasSize(20); // 160-bit
    }

    @Test
    void verifies_currentStep_andAdvancesFloor() {
        String secret = totp.newSecret();
        Instant now = Instant.parse("2026-06-18T12:00:00Z");
        long step = totp.currentCounter(now);
        String code = codeFor(secret, step);

        long matched = totp.verifyAt(secret, -1L, code, now);
        assertThat(matched).isEqualTo(step);
    }

    @Test
    void acceptsPlusMinusOneStepSkew() {
        String secret = totp.newSecret();
        Instant now = Instant.parse("2026-06-18T12:00:00Z");
        long step = totp.currentCounter(now);

        assertThat(totp.verifyAt(secret, -1L, codeFor(secret, step - 1), now)).isEqualTo(step - 1);
        assertThat(totp.verifyAt(secret, -1L, codeFor(secret, step + 1), now)).isEqualTo(step + 1);
        // ±2 is OUTSIDE the window.
        assertThat(totp.verifyAt(secret, -1L, codeFor(secret, step + 2), now)).isEqualTo(-1L);
    }

    @Test
    void rejectsReplayOfJustUsedStep() {
        String secret = totp.newSecret();
        Instant now = Instant.parse("2026-06-18T12:00:00Z");
        long step = totp.currentCounter(now);
        String code = codeFor(secret, step);

        long matched = totp.verifyAt(secret, -1L, code, now);
        assertThat(matched).isEqualTo(step);
        // Replaying the SAME code with the floor now at `step` must NOT verify.
        assertThat(totp.verifyAt(secret, matched, code, now)).isEqualTo(-1L);
        // An older step is also rejected.
        assertThat(totp.verifyAt(secret, step, codeFor(secret, step - 1), now)).isEqualTo(-1L);
    }

    @Test
    void rejectsMalformedCode() {
        String secret = totp.newSecret();
        assertThat(totp.verify(secret, -1L, "abc")).isEqualTo(-1L);
        assertThat(totp.verify(secret, -1L, "12345")).isEqualTo(-1L);
        assertThat(totp.verify(secret, -1L, null)).isEqualTo(-1L);
        assertThat(totp.verify(null, -1L, "123456")).isEqualTo(-1L);
    }

    @Test
    void otpauthUri_carriesIssuerSecretAndParams() {
        String uri = totp.otpauthUri("alice", "ABCDEF");
        assertThat(uri).startsWith("otpauth://totp/Snapdragon:alice");
        assertThat(uri).contains("secret=ABCDEF").contains("issuer=Snapdragon")
                .contains("algorithm=SHA1").contains("digits=6").contains("period=30");
    }

    @Test
    void base32_roundTrips() {
        byte[] raw = {0, 1, 2, (byte) 255, 16, 32, 64, (byte) 200, 7, 9};
        assertThat(TotpService.base32Decode(TotpService.base32Encode(raw))).isEqualTo(raw);
    }
}

package systems.hugmesh.authcore.mfa;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AES-256-GCM at-rest cipher: round-trip, per-record random nonce (two encryptions of the
 * same plaintext differ), tamper-detection (a flipped byte fails the GCM tag -> null), and
 * the dark-safe INERT posture when no key is configured.
 */
class MfaSecretCipherTest {

    private final MfaSecretCipher cipher = new MfaSecretCipher(
            Base64.getEncoder().encodeToString(new byte[32])); // 32-byte test key

    @Test
    void roundTrips() {
        String secret = "JBSWY3DPEHPK3PXP";
        String enc = cipher.encrypt(secret);
        assertThat(enc).isNotEqualTo(secret);
        assertThat(cipher.decrypt(enc)).isEqualTo(secret);
    }

    @Test
    void usesFreshNoncePerRecord() {
        String secret = "JBSWY3DPEHPK3PXP";
        assertThat(cipher.encrypt(secret)).isNotEqualTo(cipher.encrypt(secret));
    }

    @Test
    void tamperedBlobFailsClosed() {
        String enc = cipher.encrypt("JBSWY3DPEHPK3PXP");
        byte[] raw = Base64.getDecoder().decode(enc);
        raw[raw.length - 1] ^= 0x01; // flip a tag byte
        assertThat(cipher.decrypt(Base64.getEncoder().encodeToString(raw))).isNull();
        assertThat(cipher.decrypt("not-base64!!!")).isNull();
        assertThat(cipher.decrypt(null)).isNull();
    }

    @Test
    void wrongKeyCannotDecrypt() {
        String enc = cipher.encrypt("JBSWY3DPEHPK3PXP");
        byte[] otherKey = new byte[32];
        otherKey[0] = 1;
        MfaSecretCipher other = new MfaSecretCipher(Base64.getEncoder().encodeToString(otherKey));
        assertThat(other.decrypt(enc)).isNull();
    }

    @Test
    void unconfiguredCipherIsInert() {
        MfaSecretCipher inert = new MfaSecretCipher("");
        assertThat(inert.isAvailable()).isFalse();
        assertThat(inert.decrypt("anything")).isNull();
    }

    @Test
    void passphraseIsFoldedToAKey() {
        MfaSecretCipher pass = new MfaSecretCipher("a-human-passphrase-not-32-bytes");
        assertThat(pass.isAvailable()).isTrue();
        String enc = pass.encrypt("JBSWY3DPEHPK3PXP");
        assertThat(pass.decrypt(enc)).isEqualTo("JBSWY3DPEHPK3PXP");
    }
}

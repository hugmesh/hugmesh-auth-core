package systems.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the OIDC token-at-rest cipher: round-trip, dark posture (no key),
 * tamper/fail-closed decryption, and key-derivation from both a raw 32-byte base64 key and an
 * arbitrary passphrase.
 */
class BffCustodyCipherTest {

    private static final String B64_KEY =
            Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes()); // 32 bytes

    @Test
    void roundTripsWithBase64Key() {
        BffCustodyCipher cipher = new BffCustodyCipher(B64_KEY);
        assertThat(cipher.isAvailable()).isTrue();

        String secret = "casdoor-access-token.eyJhbGciOi.sig";
        String blob = cipher.encrypt(secret);

        assertThat(blob).isNotEqualTo(secret);          // actually encrypted
        assertThat(cipher.decrypt(blob)).isEqualTo(secret);
    }

    @Test
    void usesFreshNoncePerCall() {
        BffCustodyCipher cipher = new BffCustodyCipher(B64_KEY);
        // Same plaintext -> different ciphertext (random 96-bit nonce), both decrypt back.
        String a = cipher.encrypt("tok");
        String b = cipher.encrypt("tok");
        assertThat(a).isNotEqualTo(b);
        assertThat(cipher.decrypt(a)).isEqualTo("tok");
        assertThat(cipher.decrypt(b)).isEqualTo("tok");
    }

    @Test
    void passphraseIsFoldedToKey() {
        BffCustodyCipher cipher = new BffCustodyCipher("some-operator-passphrase-not-base64-32");
        assertThat(cipher.isAvailable()).isTrue();
        assertThat(cipher.decrypt(cipher.encrypt("rt"))).isEqualTo("rt");
    }

    @Test
    void darkWhenNoKey() {
        BffCustodyCipher cipher = new BffCustodyCipher("");
        assertThat(cipher.isAvailable()).isFalse();
        assertThat(cipher.decrypt("anything")).isNull();           // fail-closed, never throws
        assertThatThrownBy(() -> cipher.encrypt("x"))
                .isInstanceOf(IllegalStateException.class);        // encrypt requires a key
    }

    @Test
    void decryptFailsClosedOnTamperOrGarbage() {
        BffCustodyCipher cipher = new BffCustodyCipher(B64_KEY);
        String blob = cipher.encrypt("payload");

        // Flip a byte in the middle of the base64 blob -> GCM tag mismatch -> null (not throw).
        char[] chars = blob.toCharArray();
        int mid = chars.length / 2;
        chars[mid] = chars[mid] == 'A' ? 'B' : 'A';
        assertThat(cipher.decrypt(new String(chars))).isNull();

        assertThat(cipher.decrypt("not-base64!!")).isNull();
        assertThat(cipher.decrypt("")).isNull();
        assertThat(cipher.decrypt(null)).isNull();

        // A different key cannot decrypt another key's blob.
        BffCustodyCipher other = new BffCustodyCipher("different-key-entirely");
        assertThat(other.decrypt(blob)).isNull();
    }
}

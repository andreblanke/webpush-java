package nl.martijndwars.webpush;

import java.security.*;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import nl.martijndwars.webpush.util.ECKeys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import static nl.martijndwars.webpush.Encoding.AES_128_GCM;

final class HttpEceTest {

    private byte[] decode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    @Test
    public void testZeroSaltAndKey() throws GeneralSecurityException {
        HttpEce httpEce = new HttpEce();
        String plaintext = "Hello";
        byte[] salt = new byte[16];
        byte[] key = new byte[16];
        byte[] actual = httpEce.encrypt(plaintext.getBytes(), salt, key, null, null, null, AES_128_GCM);
        byte[] expected = decode("AAAAAAAAAAAAAAAAAAAAAAAAEAAAMpsi6NfZUkOdJI96XyX0tavLqyIdiw");

        assertArrayEquals(expected, actual);
    }

    /**
     * See <a href="https://www.rfc-editor.org/rfc/rfc8188#section-3.1">3.1. Encryption of a Response</a>
     * <p>
     * - Record size is 4096.
     * - Input keying material is identified by an empty string.
     */
    @Test
    public void testSampleEncryption() throws GeneralSecurityException {
        HttpEce httpEce = new HttpEce();

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode("I1BsxtFttlv3u_Oo94xnmw");
        byte[] key = decode("yqdlZ-tYemfogSmv7Ws5PQ");
        byte[] actual = httpEce.encrypt(plaintext, salt, key, null, null, null, AES_128_GCM);
        byte[] expected = decode("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testSampleEncryptDecrypt() throws GeneralSecurityException {
        String encodedPrivateKey = "yqdlZ-tYemfogSmv7Ws5PQ";
        // Can no longer be simply derived from the encodedPrivateKey with plain JCA functionality.
        String encodedPublicKey = "BERIZW3tEwt3atwS7-oDtzs-ryp6Ap9MfsSMwWqPSksROPcAOgu7FXVqcMX3khhAiTnZYDSNCSDDFW8GkxxtAVE=";
        String encodedSalt = "I1BsxtFttlv3u_Oo94xnmw";

        // Prepare the key map, which maps a keyid to a keypair.
        PrivateKey privateKey = ECKeys.loadPrivateKey(encodedPrivateKey);
        PublicKey publicKey = ECKeys.loadPublicKey(encodedPublicKey);

        final var keys   = Map.of("", new KeyPair(publicKey, privateKey));
        final var labels = Map.of("", "P-256");

        // Run the encryption and decryption
        final var httpEce = new HttpEce(keys, labels);

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode(encodedSalt);
        byte[] key = decode(encodedPrivateKey);
        byte[] ciphertext = httpEce.encrypt(plaintext, salt, key, null, null, null, AES_128_GCM);
        byte[] decrypted = httpEce.decrypt(ciphertext, null, key, null, AES_128_GCM);

        assertArrayEquals(plaintext, decrypted);
    }

    // TODO: This test is disabled because the library does not deal with multiple records yet.
    /**
     * See <a href="https://www.rfc-editor.org/rfc/rfc8188#section-3.2">3.2. Encryption with multiple Records</a>
     */
    @Test
    @Disabled
    public void testEncryptionWithMultipleRecords() throws GeneralSecurityException {
        HttpEce httpEce = new HttpEce();

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode("uNCkWiNYzKTnBN9ji3-qWA");
        byte[] key = decode("BO3ZVPxUlnLORbVGMpbT1Q");
        byte[] actual = httpEce.encrypt(plaintext, salt, key, null, null, null, AES_128_GCM);
        byte[] expected = decode(
            "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");

        assertArrayEquals(expected, actual);
    }
}

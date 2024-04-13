package nl.martijndwars.webpush.util;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;

public final class ECKeys {

    private static final byte UNCOMPRESSED_MAGIC = 0x04;

    private static final int LENGTH = 32;

    /**
     * Encodes the provided {@link ECPublicKey} to a 65 byte array starting with the octet {@code 0x04} followed by two
     * 32 byte big endian unsigned integers representing a point {@code (x, y)} on the curve.
     *
     * @param publicKey The public key to be encoded.
     *
     * @return A byte array encoding the {@link ECPoint} retrieved from {@link ECPublicKey#getW()}.
     */
    public static byte[] encode(final ECPublicKey publicKey) {
        final ECPoint w = publicKey.getW();

        final var bytes = new byte[1 + (2 * LENGTH)];
        bytes[0] = UNCOMPRESSED_MAGIC;

        final var xBytes = BigIntegers.asUnsignedByteArray(w.getAffineX(), LENGTH);
        final var yBytes = BigIntegers.asUnsignedByteArray(w.getAffineY(), LENGTH);

        System.arraycopy(xBytes, 0, bytes, 1,                 xBytes.length);
        System.arraycopy(yBytes, 0, bytes, 1 + xBytes.length, yBytes.length);

        return bytes;
    }

    /**
     * Encodes the provided {@link ECPrivateKey} to a byte array containing the big endian signed integer representing
     * the private scalar value {@code S}.
     *
     * @param privateKey The private key to be encoded.
     *
     * @return A byte array encoding the {@link BigInteger} retrieved from {@link ECPrivateKey#getS()}.
     */
    public static byte[] encode(final ECPrivateKey privateKey) {
        return privateKey.getS().toByteArray();
    }

    public static ECPublicKey loadPublicKey(final String encodedPublicKey)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        final byte[] decodedPublicKey = Base64.getUrlDecoder().decode(encodedPublicKey);
        return loadPublicKey(decodedPublicKey);
    }

    public static ECPublicKey loadPublicKey(final byte[] uncompressedPublicKeyBytes)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        final var keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(
            new ECPublicKeySpec(decodePoint(uncompressedPublicKeyBytes), getSecp256r1ParameterSpec()));
    }

    // See org.bouncycastle.math.ec.ECCurve.decodePoint.
    private static ECPoint decodePoint(final byte[] bytes) {
        if (bytes.length != ((2 * LENGTH) + 1))
            throw new IllegalArgumentException();

        // Only uncompressed encoding is supported by this method.
        final byte type = bytes[0];
        if (bytes[0] != UNCOMPRESSED_MAGIC)
            throw new IllegalArgumentException("Invalid or unsupported point encoding 0x" + Integer.toString(type, 16));

        final var x = BigIntegers.fromUnsignedByteArray(bytes, 1,          LENGTH);
        final var y = BigIntegers.fromUnsignedByteArray(bytes, 1 + LENGTH, LENGTH);
        return new ECPoint(x, y);
    }

    public static ECPrivateKey loadPrivateKey(final String encodedPrivateKey)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        final byte[] privateKeyBytes = Base64.getUrlDecoder().decode(encodedPrivateKey);
        return loadPrivateKey(privateKeyBytes);
    }

    public static ECPrivateKey loadPrivateKey(final byte[] privateKeyBytes)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        final var keyFactory = KeyFactory.getInstance("EC");
        return (ECPrivateKey) keyFactory.generatePrivate(
            new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(privateKeyBytes), getSecp256r1ParameterSpec()));
    }

    /**
     * Generates an elliptic curve {@link KeyPair} on the {@code secp256r1} curve.
     */
    public static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        final var keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(getSecp256r1ParameterSpec());
        return keyPairGenerator.generateKeyPair();
    }

    private static ECParameterSpec getSecp256r1ParameterSpec()
            throws NoSuchAlgorithmException, InvalidParameterSpecException {
        final var algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
        return algorithmParameters.getParameterSpec(ECParameterSpec.class);
    }
}

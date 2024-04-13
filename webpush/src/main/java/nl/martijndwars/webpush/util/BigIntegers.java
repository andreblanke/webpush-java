package nl.martijndwars.webpush.util;

import java.math.BigInteger;

// See org.bouncycastle.util.BigIntegers.
@SuppressWarnings("SameParameterValue")
final class BigIntegers {

    private BigIntegers() {
    }

    static BigInteger fromUnsignedByteArray(final byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    static BigInteger fromUnsignedByteArray(final byte[] bytes, final int offset, final int length) {
        final var magnitude = new byte[length];
        System.arraycopy(bytes, offset, magnitude, 0, length);
        return new BigInteger(1, magnitude);
    }

    static byte[] asUnsignedByteArray(final BigInteger bigInteger, final int length) {
        final var bytes = bigInteger.toByteArray();
        if (bytes.length == length)
            return bytes;

        final int start = ((bytes[0] == 0) && bytes.length != 1) ? 1 : 0;
        final int count = bytes.length - start;

        final var padded = new byte[length];
        System.arraycopy(bytes, start, padded, padded.length - count, count);
        return padded;
    }
}

package nl.martijndwars.webpush;

import java.security.PublicKey;

public record Encrypted(PublicKey publicKey, byte[] salt, byte[] ciphertext) {

    public static final class Builder {

        private PublicKey publicKey;
        private byte[] salt;
        private byte[] ciphertext;

        public Builder withPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;

            return this;
        }

        public Builder withSalt(byte[] salt) {
            this.salt = salt;

            return this;
        }

        public Builder withCiphertext(byte[] ciphertext) {
            this.ciphertext = ciphertext;

            return this;
        }

        public Encrypted build() {
            return new Encrypted(publicKey, salt, ciphertext);
        }
    }
}

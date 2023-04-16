package nl.martijndwars.webpush;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

public abstract class AbstractPushService<T extends AbstractPushService<T>> {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final String SERVER_KEY_ID = "server-key-id";
    public static final String SERVER_KEY_CURVE = "P-256";

    /**
     * The Google Cloud Messaging API key (for pre-VAPID in Chrome)
     */
    private String gcmApiKey;

    /**
     * Subject used in the JWT payload (for VAPID). When left as null, then no subject will be used
     * (RFC-8292 2.1 says that it is optional)
     */
    private String subject;

    /**
     * The public key (for VAPID)
     */
    private PublicKey publicKey;

    /**
     * The private key (for VAPID)
     */
    private PrivateKey privateKey;

    public AbstractPushService() {
    }

    public AbstractPushService(String gcmApiKey) {
        this.gcmApiKey = gcmApiKey;
    }

    public AbstractPushService(KeyPair keyPair) {
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public AbstractPushService(KeyPair keyPair, String subject) {
        this(keyPair);
        this.subject = subject;
    }

    public AbstractPushService(String publicKey, String privateKey) throws GeneralSecurityException {
        this.publicKey = Utils.loadPublicKey(publicKey);
        this.privateKey = Utils.loadPrivateKey(privateKey);
    }

    public AbstractPushService(String publicKey, String privateKey, String subject) throws GeneralSecurityException {
        this(publicKey, privateKey);
        this.subject = subject;
    }

    /**
     * Encrypt the payload.
     * <p>
     * Encryption uses Elliptic curve Diffie-Hellman (ECDH) cryptography over the prime256v1 curve.
     *
     * @param payload       Payload to encrypt.
     * @param userPublicKey The user agent's public key (keys.p256dh).
     * @param userAuth      The user agent's authentication secret (keys.auth).
     *
     * @return An Encrypted object containing the public key, salt, and ciphertext.
     */
    public static Encrypted encrypt(byte[] payload, ECPublicKey userPublicKey, byte[] userAuth, Encoding encoding) throws GeneralSecurityException {
        KeyPair localKeyPair = generateLocalKeyPair();

        Map<String, KeyPair> keys = new HashMap<>();
        keys.put(SERVER_KEY_ID, localKeyPair);

        Map<String, String> labels = new HashMap<>();
        labels.put(SERVER_KEY_ID, SERVER_KEY_CURVE);

        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        HttpEce httpEce = new HttpEce(keys, labels);
        byte[] ciphertext = httpEce.encrypt(payload, salt, null, SERVER_KEY_ID, userPublicKey, userAuth, encoding);

        return new Encrypted.Builder()
                .withSalt(salt)
                .withPublicKey(localKeyPair.getPublic())
                .withCiphertext(ciphertext)
                .build();
    }

    /**
     * Generate the local (ephemeral) keys.
     */
    private static KeyPair generateLocalKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(parameterSpec);

        return keyPairGenerator.generateKeyPair();
    }

    protected final HttpRequest prepareRequest(Notification notification, Encoding encoding) throws GeneralSecurityException, IOException, JoseException, URISyntaxException {
        if (getPrivateKey() != null && getPublicKey() != null) {
            if (!Utils.verifyKeyPair(getPrivateKey(), getPublicKey())) {
                throw new IllegalStateException("Public key and private key do not match.");
            }
        }

        Encrypted encrypted = encrypt(
            notification.getPayload(),
            notification.getUserPublicKey(),
            notification.getUserAuth(),
            encoding
        );

        byte[] dh = Utils.encode((ECPublicKey) encrypted.getPublicKey());
        byte[] salt = encrypted.getSalt();

        final var builder = HttpRequest.newBuilder(new URI(notification.getEndpoint()))
            .header("TTL", String.valueOf(notification.getTTL()));

        final var cryptoKeyHeader = new HashMap<String, String>();

        if (notification.hasUrgency()) {
            builder.header("Urgency", notification.getUrgency().getHeaderValue());
        }

        if (notification.hasTopic()) {
            builder.header("Topic", notification.getTopic());
        }

        final BodyPublisher bodyPublisher;
        if (notification.hasPayload()) {
            builder.header("Content-Type", "application/octet-stream");

            if (encoding == Encoding.AES_128_GCM) {
                builder.header("Content-Encoding", "aes128gcm");
            } else if (encoding == Encoding.AES_GCM) {
                builder.header("Content-Encoding", "aesgcm");
                builder.header("Encryption", "salt=" + Base64.getUrlEncoder().withoutPadding().encodeToString(salt));

                cryptoKeyHeader.put("dh", Base64.getUrlEncoder().encodeToString(dh));
            }

            bodyPublisher = HttpRequest.BodyPublishers.ofByteArray(encrypted.getCiphertext());
        } else {
            bodyPublisher = HttpRequest.BodyPublishers.noBody();
        }

        if (notification.isGcm()) {
            if (getGcmApiKey() == null) {
                throw new IllegalStateException("An GCM API key is needed to send a push notification to a GCM endpoint.");
            }

            builder.header("Authorization", "key=" + getGcmApiKey());
        } else if (vapidEnabled()) {
            if (encoding == Encoding.AES_128_GCM && notification.getEndpoint().startsWith("https://fcm.googleapis.com")) {
                builder.uri(new URI(notification.getEndpoint().replace("fcm/send", "wp")));
            }

            final var claims = new JwtClaims();
            claims.setAudience(notification.getOrigin());
            claims.setExpirationTimeMinutesInTheFuture(12 * 60);
            if (getSubject() != null) {
                claims.setSubject(getSubject());
            }

            final var jws = new JsonWebSignature();
            jws.setHeader("typ", "JWT");
            jws.setHeader("alg", "ES256");
            jws.setPayload(claims.toJson());
            jws.setKey(getPrivateKey());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

            byte[] pk = Utils.encode((ECPublicKey) getPublicKey());

            switch (encoding) {
                case AES_128_GCM:
                    builder.header("Authorization", "vapid t=" + jws.getCompactSerialization() + ", k=" + Base64.getUrlEncoder().withoutPadding().encodeToString(pk));
                    break;
                case AES_GCM:
                    builder.header("Authorization", "WebPush " + jws.getCompactSerialization());
                    break;
            }
            cryptoKeyHeader.put("p256ecdsa", Base64.getUrlEncoder().encodeToString(pk));
        } else if (notification.isFcm() && getGcmApiKey() != null) {
            builder.header("Authorization", "key=" + getGcmApiKey());
        }

        if (!cryptoKeyHeader.isEmpty()) {
            final var joiner = new StringJoiner(";");
            cryptoKeyHeader.forEach((name, value) -> joiner.add(name + '=' + value));
            builder.header("Crypto-Key", joiner.toString());
        }

        return builder.POST(bodyPublisher).build();
    }

    /**
     * Set the Google Cloud Messaging (GCM) API key
     */
    public T setGcmApiKey(String gcmApiKey) {
        this.gcmApiKey = gcmApiKey;

        return (T) this;
    }

    public String getGcmApiKey() {
        return gcmApiKey;
    }

    public String getSubject() {
        return subject;
    }

    /**
     * Set the JWT subject (for VAPID)
     */
    public T setSubject(String subject) {
        this.subject = subject;

        return (T) this;
    }

    /**
     * Set the public and private key (for VAPID).
     */
    public T setKeyPair(KeyPair keyPair) {
        setPublicKey(keyPair.getPublic());
        setPrivateKey(keyPair.getPrivate());

        return (T) this;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Set the public key using a base64url-encoded string.
     */
    public T setPublicKey(String publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        setPublicKey(Utils.loadPublicKey(publicKey));

        return (T) this;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public KeyPair getKeyPair() {
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Set the public key (for VAPID)
     */
    public T setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;

        return (T) this;
    }

    /**
     * Set the public key using a base64url-encoded string.
     */
    public T setPrivateKey(String privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        setPrivateKey(Utils.loadPrivateKey(privateKey));

        return (T) this;
    }

    /**
     * Set the private key (for VAPID)
     */
    public T setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;

        return (T) this;
    }

    /**
     * Check if VAPID is enabled
     */
    protected boolean vapidEnabled() {
        return publicKey != null && privateKey != null;
    }
}

package dev.blanke.webpush;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dev.blanke.webpush.jwt.Jose4jJwtFactory;
import dev.blanke.webpush.jwt.JwtFactory;

public abstract class AbstractPushService implements PushService {

    /**
     * The Google Cloud Messaging API key (for pre-VAPID in Chrome)
     */
    private final String gcmApiKey;

    /**
     * Subject used in the JWT payload (for VAPID). When left as {@code null}, then no subject will be used
     * (RFC-8292 2.1 says that it is optional)
     */
    private final String vapidSubject;

    private final KeyPair vapidKeyPair;

    private final JwtFactory jwtFactory;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final Logger LOGGER = System.getLogger(AbstractPushService.class.getName());

    public static final String SERVER_KEY_ID = "server-key-id";

    public static final String SERVER_KEY_CURVE = "P-256";

    protected AbstractPushService(final Builder<?> builder) {
        this.gcmApiKey    = builder.gcmApiKey;
        this.vapidKeyPair = builder.vapidKeyPair;
        this.vapidSubject = builder.vapidSubject;

        if (builder.jwtFactory == null) {
            LOGGER.log(Level.WARNING,
                "No JwtFactory was specified. Falling back to dev.blanke.webpush.jwt.Jose4jJwtFactory...");
            builder.jwtFactory = new Jose4jJwtFactory();
        }
        this.jwtFactory = builder.jwtFactory;
    }

    @Override
    public void close() {
    }

    protected final HttpRequest prepareRequest(final Notification notification, final Encoding encoding)
            throws GeneralSecurityException, URISyntaxException {
        if (isVapidEnabled() && !Utils.verifyKeyPair(getVapidPrivateKey(), getVapidPublicKey())) {
            throw new IllegalStateException("Public key and private key do not match.");
        }

        final Encrypted encrypted = encrypt(
            notification.payload(),
            notification.userPublicKey(),
            notification.userAuth(),
            encoding
        );

        final var builder = HttpRequest.newBuilder(notification.endpoint())
            .header("TTL", String.valueOf(notification.ttl()));

        final var cryptoKeyHeader = new HashMap<String, String>();

        if (notification.hasUrgency()) {
            builder.header("Urgency", notification.urgency().getHeaderValue());
        }

        if (notification.hasTopic()) {
            builder.header("Topic", notification.topic());
        }

        final BodyPublisher bodyPublisher;
        if (notification.hasPayload()) {
            builder.header("Content-Type", "application/octet-stream");

            if (encoding == Encoding.AES_128_GCM) {
                builder.header("Content-Encoding", "aes128gcm");
            } else if (encoding == Encoding.AES_GCM) {
                builder.header("Content-Encoding", "aesgcm");
                builder.header("Encryption", "salt=" + Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted.salt()));

                byte[] dh = Utils.encode(encrypted.publicKey());
                cryptoKeyHeader.put("dh", Base64.getUrlEncoder().encodeToString(dh));
            }

            bodyPublisher = HttpRequest.BodyPublishers.ofByteArray(encrypted.ciphertext());
        } else {
            bodyPublisher = HttpRequest.BodyPublishers.noBody();
        }

        if (notification.isGcm()) {
            if (getGcmApiKey() == null) {
                throw new IllegalStateException("An GCM API key is needed to send a push notification to a GCM endpoint.");
            }

            builder.header("Authorization", "key=" + getGcmApiKey());
        } else if (isVapidEnabled()) {
            if (encoding == Encoding.AES_128_GCM && notification.isFcm()) {
                builder.uri(new URI(notification.endpoint().toString().replace("fcm/send", "wp")));
            }

            final var publicKey = Utils.encode((ECPublicKey) getVapidPublicKey());
            final var token = jwtFactory.serialize(
                Map.of(
                    "typ", "JWT",
                    "alg", "ES256"),
                Map.of(
                    "aud", notification.getOrigin(),
                    "exp", Instant.now().plus(Duration.ofMinutes(20)).getEpochSecond(),
                    "sub", getVapidSubject()),
                getVapidPrivateKey());

            switch (encoding) {
                case AES_128_GCM ->
                    builder.header("Authorization", "vapid t=%s, k=%s".formatted(
                        token, Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)));
                case AES_GCM -> builder.header("Authorization", "WebPush %s".formatted(token));
            }
            cryptoKeyHeader.put("p256ecdsa", Base64.getUrlEncoder().encodeToString(publicKey));
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

    public record Encrypted(ECPublicKey publicKey, byte[] salt, byte[] ciphertext) {}

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
    private static Encrypted encrypt(final byte[] payload, final ECPublicKey userPublicKey, final byte[] userAuth,
                                     final Encoding encoding) throws GeneralSecurityException {
        final KeyPair localKeyPair = generateLocalKeyPair();

        final var keys   = Map.of(SERVER_KEY_ID, localKeyPair);
        final var labels = Map.of(SERVER_KEY_ID, SERVER_KEY_CURVE);
        final var httpEce = new HttpEce(keys, labels);

        final var salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        final var ciphertext = httpEce.encrypt(payload, salt, null, SERVER_KEY_ID, userPublicKey, userAuth, encoding);
        return new Encrypted((ECPublicKey) localKeyPair.getPublic(), salt, ciphertext);
    }

    /**
     * Generates the local (ephemeral) keys.
     */
    private static KeyPair generateLocalKeyPair() throws GeneralSecurityException {
        final var parameterSpec = ECNamedCurveTable.getParameterSpec(Utils.CURVE);

        final var keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(parameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public String getGcmApiKey() {
        return gcmApiKey;
    }

    @Override
    public String getVapidSubject() {
        return vapidSubject;
    }

    @Override
    public KeyPair getVapidKeyPair() {
        return vapidKeyPair;
    }
}

package nl.martijndwars.webpush;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @param endpoint The endpoint associated with the push subscription
 * @param userPublicKey The client's public key
 * @param userAuth The client's auth
 * @param payload An arbitrary payload
 * @param urgency Push Message Urgency <a href="https://tools.ietf.org/html/rfc8030#section-5.3">Push Message Urgency</a>
 * @param topic Push Message Topic <a href="https://tools.ietf.org/html/rfc8030#section-5.4">Replacing Push Messages</a>
 * @param ttl Time in seconds that the push message is retained by the push service
 */
public record Notification(URI endpoint, ECPublicKey userPublicKey, byte[] userAuth, byte[] payload, Urgency urgency,
                           String topic, int ttl) {

    private static final int ONE_DAY_DURATION_IN_SECONDS = 86_400;

    private static final int DEFAULT_TTL = 28 * ONE_DAY_DURATION_IN_SECONDS;

    public boolean hasPayload() {
        return (payload().length > 0);
    }

    public boolean hasUrgency() {
        return (urgency != null);
    }

    public boolean hasTopic() {
        return (topic != null);
    }

    /**
     * Detect if the notification is for a GCM-based subscription
     */
    public boolean isGcm() {
        return endpoint().toString().startsWith("https://android.googleapis.com/gcm/send");
    }

    public boolean isFcm() {
        return endpoint().toString().startsWith("https://fcm.googleapis.com/fcm/send");
    }

    public String getOrigin() throws URISyntaxException {
        final var origin = new URI(endpoint().getScheme(), endpoint().getHost(), null, null);
        return origin.toString();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Web Push Message Urgency header field values
     *
     *  @see <a href="https://tools.ietf.org/html/rfc8030#section-5.3">Push Message Urgency</a>
     */
    public enum Urgency {

        VERY_LOW("very-low"),
        LOW("low"),
        NORMAL("normal"),
        HIGH("high");

        private final String headerValue;

        Urgency(String urgency) {
            this.headerValue = urgency;
        }

        public String getHeaderValue() {
            return headerValue;
        }
    }

    @SuppressWarnings("unused")
    public static final class Builder {

        private String endpoint = null;

        private ECPublicKey userPublicKey = null;

        private byte[] userAuth = null;

        private byte[] payload = null;

        private int ttl = DEFAULT_TTL;

        private Urgency urgency = null;

        private String topic = null;

        private Builder() {
        }

        public Notification build() {
            return new Notification(URI.create(endpoint), userPublicKey, userAuth, payload, urgency, topic, ttl);
        }

        public Builder endpoint(final String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder endpoint(final URI endpoint) {
            this.endpoint = endpoint.toString();
            return this;
        }

        public Builder userPublicKey(final PublicKey publicKey) {
            this.userPublicKey = (ECPublicKey) publicKey;
            return this;
        }

        public Builder userPublicKey(final String publicKey)
                throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            this.userPublicKey = (ECPublicKey) Utils.loadPublicKey(publicKey);
            return this;
        }

        public Builder userPublicKey(final byte[] publicKey)
                throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            this.userPublicKey = (ECPublicKey) Utils.loadPublicKey(publicKey);
            return this;
        }

        public Builder userAuth(final String userAuth) {
            this.userAuth = Base64.getUrlDecoder().decode(userAuth);
            return this;
        }

        public Builder userAuth(final byte[] userAuth) {
            this.userAuth = userAuth;
            return this;
        }

        public Builder payload(final byte[] payload) {
            this.payload = payload;
            return this;
        }

        public Builder payload(final String payload) {
            this.payload = payload.getBytes(UTF_8);
            return this;
        }

        public Builder ttl(final int ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder urgency(final Urgency urgency) {
            this.urgency = urgency;
            return this;
        }

        public Builder topic(final String topic) {
            this.topic = topic;
            return this;
        }

        public Builder subscription(final Subscription subscription)
                throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
            return endpoint(subscription.endpoint())
                .userPublicKey(subscription.keys().p256dh())
                .userAuth(subscription.keys().auth());
        }
    }
}

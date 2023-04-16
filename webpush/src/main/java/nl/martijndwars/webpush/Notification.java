package nl.martijndwars.webpush;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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
public record Notification(String endpoint, ECPublicKey userPublicKey, byte[] userAuth, byte[] payload, Urgency urgency, String topic, int ttl) {

    private static final int ONE_DAY_DURATION_IN_SECONDS = 86400;
    private static final int DEFAULT_TTL = 28 * ONE_DAY_DURATION_IN_SECONDS;

    public boolean hasPayload() {
        return payload().length > 0;
    }

    public boolean hasUrgency() {
        return urgency != null;
    }

    public boolean hasTopic() {
        return topic != null;
    }

    /**
     * Detect if the notification is for a GCM-based subscription
     */
    public boolean isGcm() {
        return endpoint().indexOf("https://android.googleapis.com/gcm/send") == 0;
    }

    public boolean isFcm() {
        return endpoint().indexOf("https://fcm.googleapis.com/fcm/send") == 0;
    }

    public int getTTL() {
        return ttl;
    }

    public Urgency getUrgency() {
        return urgency;
    }

    public String getTopic() {
        return topic;
    }

    public String getOrigin() throws MalformedURLException {
        URL url = new URL(endpoint());

        return url.getProtocol() + "://" + url.getHost();
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
            return new Notification(endpoint, userPublicKey, userAuth, payload, urgency, topic, ttl);
        }

        public Builder endpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder userPublicKey(PublicKey publicKey) {
            this.userPublicKey = (ECPublicKey) publicKey;
            return this;
        }

        public Builder userPublicKey(String publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            this.userPublicKey = (ECPublicKey) Utils.loadPublicKey(publicKey);
            return this;
        }

        public Builder userPublicKey(byte[] publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            this.userPublicKey = (ECPublicKey) Utils.loadPublicKey(publicKey);
            return this;
        }

        public Builder userAuth(String userAuth) {
            this.userAuth = Base64.getUrlDecoder().decode(userAuth);
            return this;
        }

        public Builder userAuth(byte[] userAuth) {
            this.userAuth = userAuth;
            return this;
        }

        public Builder payload(byte[] payload) {
            this.payload = payload;
            return this;
        }

        public Builder payload(String payload) {
            this.payload = payload.getBytes(UTF_8);
            return this;
        }

        public Builder ttl(int ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder urgency(Urgency urgency) {
            this.urgency = urgency;
            return this;
        }

        public Builder topic(String topic) {
            this.topic = topic;
            return this;
        }

        public Builder subscription(Subscription subscription) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
            return endpoint(subscription.endpoint())
                .userPublicKey(subscription.keys().p256dh())
                .userAuth(subscription.keys().auth());
        }
    }
}

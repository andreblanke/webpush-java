package nl.martijndwars.webpush;

import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.util.concurrent.CompletableFuture;

import nl.martijndwars.webpush.jwt.JwtFactory;
import nl.martijndwars.webpush.util.ECKeys;

@SuppressWarnings("unused")
public interface PushService extends AutoCloseable {

    Encoding DEFAULT_ENCODING = Encoding.AES_128_GCM;

    static JdkHttpClientPushService.Builder builder() {
        return new JdkHttpClientPushService.Builder();
    }

    String getGcmApiKey();

    KeyPair getVapidKeyPair();

    default ECPublicKey getVapidPublicKey() {
        return (ECPublicKey) getVapidKeyPair().getPublic();
    }

    default ECPrivateKey getVapidPrivateKey() {
        return (ECPrivateKey) getVapidKeyPair().getPrivate();
    }

    default boolean isVapidEnabled() {
        final var vapidKeyPair = getVapidKeyPair();
        return (vapidKeyPair.getPublic() != null) && (vapidKeyPair.getPrivate() != null);
    }

    String getVapidSubject();

    default HttpResponse<Void> send(final Notification notification) throws Exception {
        return send(notification, DEFAULT_ENCODING);
    }

    default HttpResponse<Void> send(Notification notification, Encoding encoding) throws Exception {
        return send(notification, encoding, BodyHandlers.discarding());
    }

    <T> HttpResponse<T> send(Notification notification, Encoding encoding, BodyHandler<T> bodyHandler) throws Exception;

    default CompletableFuture<HttpResponse<Void>> sendAsync(final Notification notification) throws Exception {
        return sendAsync(notification, DEFAULT_ENCODING);
    }

    default CompletableFuture<HttpResponse<Void>> sendAsync(Notification notification, Encoding encoding)
            throws Exception {
        return sendAsync(notification, encoding, BodyHandlers.discarding());
    }

    <T> CompletableFuture<HttpResponse<T>> sendAsync(Notification notification, Encoding encoding,
                                                     BodyHandler<T> bodyHandler) throws Exception;

    @SuppressWarnings("unchecked")
    abstract class Builder<T extends Builder<T>> {

        protected Clock clock;

        protected String gcmApiKey;

        protected KeyPair vapidKeyPair;

        protected String vapidSubject;

        protected JwtFactory jwtFactory;

        abstract PushService build();

        public T withClock(final Clock clock) {
            this.clock = clock;
            return (T) this;
        }

        public T withGcmApiKey(final String gcmApiKey) {
            this.gcmApiKey = gcmApiKey;
            return (T) this;
        }

        public T withVapidKeyPair(final KeyPair vapidKeyPair) {
            this.vapidKeyPair = vapidKeyPair;
            return (T) this;
        }

        public T withVapidPublicKey(final String encodedVapidPublicKey) throws GeneralSecurityException {
            return withVapidPublicKey(ECKeys.loadPublicKey(encodedVapidPublicKey));
        }

        public T withVapidPublicKey(final ECPublicKey vapidPublicKey) {
            final var vapidPrivateKey = (vapidKeyPair != null) ? vapidKeyPair.getPrivate() : null;
            vapidKeyPair = new KeyPair(vapidPublicKey, vapidPrivateKey);
            return (T) this;
        }

        public T withVapidPrivateKey(final String encodedVapidPrivateKey) throws GeneralSecurityException {
            return withVapidPrivateKey(ECKeys.loadPrivateKey(encodedVapidPrivateKey));
        }

        public T withVapidPrivateKey(final ECPrivateKey vapidPrivateKey) {
            final var vapidPublicKey = (vapidKeyPair != null) ? vapidKeyPair.getPublic() : null;
            vapidKeyPair = new KeyPair(vapidPublicKey, vapidPrivateKey);
            return (T) this;
        }

        public T withVapidSubject(final String vapidSubject) {
            this.vapidSubject = vapidSubject;
            return (T) this;
        }

        public T withJwtFactory(final JwtFactory jwtFactory) {
            this.jwtFactory = jwtFactory;
            return (T) this;
        }
    }
}

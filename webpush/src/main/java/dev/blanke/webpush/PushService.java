package dev.blanke.webpush;

import dev.blanke.webpush.jwt.JwtFactory;

import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.CompletableFuture;

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

    HttpResponse<Void> send(Notification notification, Encoding encoding) throws Exception;

    default CompletableFuture<HttpResponse<Void>> sendAsync(final Notification notification) throws Exception {
        return sendAsync(notification, DEFAULT_ENCODING);
    }

    CompletableFuture<HttpResponse<Void>> sendAsync(Notification notification, Encoding encoding) throws Exception;

    @SuppressWarnings("unchecked")
    abstract class Builder<T extends Builder<T>> {

        protected String gcmApiKey;

        protected KeyPair vapidKeyPair;

        protected String vapidSubject;

        protected JwtFactory jwtFactory;

        abstract PushService build();

        public T withGcmApiKey(final String gcmApiKey) {
            this.gcmApiKey = gcmApiKey;
            return (T) this;
        }

        public T withVapidKeyPair(final KeyPair vapidKeyPair) {
            this.vapidKeyPair = vapidKeyPair;
            return (T) this;
        }

        public T withVapidPublicKey(final String encodedVapidPublicKey) throws GeneralSecurityException {
            return withVapidPublicKey((ECPublicKey) Utils.loadPublicKey(encodedVapidPublicKey));
        }

        public T withVapidPublicKey(final ECPublicKey vapidPublicKey) {
            vapidKeyPair = new KeyPair(vapidPublicKey, vapidKeyPair.getPrivate());
            return (T) this;
        }

        public T withVapidPrivateKey(final String encodedVapidPrivateKey) throws GeneralSecurityException {
            return withVapidPrivateKey((ECPrivateKey) Utils.loadPrivateKey(encodedVapidPrivateKey));
        }

        public T withVapidPrivateKey(final ECPrivateKey vapidPrivateKey) {
            vapidKeyPair = new KeyPair(vapidKeyPair.getPublic(), vapidPrivateKey);
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

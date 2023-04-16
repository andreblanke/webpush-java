package nl.martijndwars.webpush;

import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public class PushService extends AbstractPushService<PushService> {

    private final HttpClient httpClient;

    public PushService(HttpClient httpClient) {
        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public PushService(HttpClient httpClient, String gcmApiKey) {
        super(gcmApiKey);

        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public PushService(HttpClient httpClient, KeyPair keyPair) {
        super(keyPair);

        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public PushService(HttpClient httpClient, KeyPair keyPair, String subject) {
        super(keyPair, subject);

        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public PushService(HttpClient httpClient, String publicKey, String privateKey) throws GeneralSecurityException {
        super(publicKey, privateKey);

        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public PushService(HttpClient httpClient, String publicKey, String privateKey, String subject) throws GeneralSecurityException {
        super(publicKey, privateKey, subject);

        this.httpClient = Objects.requireNonNull(httpClient);
    }

    public HttpResponse<?> send(Notification notification) throws JoseException, GeneralSecurityException, IOException, URISyntaxException, InterruptedException {
        return send(notification, Encoding.AES_GCM);
    }

    public HttpResponse<?> send(Notification notification, Encoding encoding) throws JoseException, GeneralSecurityException, IOException, URISyntaxException, InterruptedException {
        return httpClient.send(prepareRequest(notification, encoding), HttpResponse.BodyHandlers.discarding());
    }

    public CompletableFuture<HttpResponse<Void>> sendAsync(Notification notification) throws GeneralSecurityException, IOException, JoseException, URISyntaxException {
        return sendAsync(notification, Encoding.AES_128_GCM);
    }

    public CompletableFuture<HttpResponse<Void>> sendAsync(Notification notification, Encoding encoding) throws JoseException, GeneralSecurityException, IOException, URISyntaxException {
        return httpClient.sendAsync(prepareRequest(notification, encoding), HttpResponse.BodyHandlers.discarding());
    }
}

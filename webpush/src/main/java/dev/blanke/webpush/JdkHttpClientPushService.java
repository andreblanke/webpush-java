package dev.blanke.webpush;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public final class JdkHttpClientPushService extends AbstractPushService {

    private final HttpClient httpClient;

    private JdkHttpClientPushService(final Builder builder) {
        super(builder);

        this.httpClient = (builder.httpClient != null) ? builder.httpClient : HttpClient.newHttpClient();
    }

    @Override
    public HttpResponse<Void> send(final Notification notification, final Encoding encoding) throws Exception {
        return httpClient.send(prepareRequest(notification, encoding), HttpResponse.BodyHandlers.discarding());
    }

    @Override
    public CompletableFuture<HttpResponse<Void>> sendAsync(final Notification notification,
                                                           final Encoding encoding) throws Exception {
        return httpClient.sendAsync(prepareRequest(notification, encoding), HttpResponse.BodyHandlers.discarding());
    }

    public static final class Builder extends PushService.Builder<Builder> {

        private HttpClient httpClient;

        @Override
        public PushService build() {
            return new JdkHttpClientPushService(this);
        }

        public Builder withHttpClient(final HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }
    }
}

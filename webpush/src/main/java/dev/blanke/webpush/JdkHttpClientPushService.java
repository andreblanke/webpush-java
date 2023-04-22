package dev.blanke.webpush;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public final class JdkHttpClientPushService extends AbstractPushService {

    private final HttpClient httpClient;

    private JdkHttpClientPushService(final Builder builder) {
        super(builder);

        this.httpClient = (builder.httpClient != null) ? builder.httpClient : HttpClient.newHttpClient();
    }

    @Override
    public <T> HttpResponse<T> send(final Notification notification, final Encoding encoding,
                                    final BodyHandler<T> bodyHandler) throws Exception {
        return httpClient.send(prepareRequest(notification, encoding), bodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(final Notification notification,
                                                            final Encoding encoding,
                                                            final BodyHandler<T> bodyHandler) throws Exception {
        return httpClient.sendAsync(prepareRequest(notification, encoding), bodyHandler);
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

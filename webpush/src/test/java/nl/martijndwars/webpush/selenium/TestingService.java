package nl.martijndwars.webpush.selenium;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Java wrapper for interacting with the Web Push Testing Service.
 */
public class TestingService {

    private final URI baseUrl;

    public TestingService(final URI baseUrl) {
        this.baseUrl = baseUrl;
    }

    public int startTestSuite() throws IOException, InterruptedException {
        final var startTestSuite = request(baseUrl.resolve("/start-test-suite"));
        return JsonParser.parseString(startTestSuite)
            .getAsJsonObject()
            .get("data")
            .getAsJsonObject()
            .get("testSuiteId")
            .getAsInt();
    }

    /**
     * Get a test ID and subscription for the given test case.
     */
    public JsonObject getSubscription(final int testSuiteId, final Configuration configuration)
            throws IOException, InterruptedException {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("testSuiteId", testSuiteId);
        jsonObject.addProperty("browserName", configuration.browser());
        jsonObject.addProperty("browserVersion", configuration.version());

        if (configuration.gcmSenderId() != null) {
            jsonObject.addProperty("gcmSenderId", configuration.gcmSenderId());
        }

        if (configuration.publicKey() != null) {
            jsonObject.addProperty("vapidPublicKey", configuration.publicKey());
        }

        final var getSubscription =
            request(baseUrl.resolve("/get-subscription"), BodyPublishers.ofString(jsonObject.toString()));
        return getData(getSubscription);
    }

    /**
     * Get the notification status for the given test case.
     */
    public JsonArray getNotificationStatus(final int testSuiteId, final int testId)
            throws IOException, InterruptedException {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("testSuiteId", testSuiteId);
        jsonObject.addProperty("testId", testId);

        final var getNotificationStatus =
            request(baseUrl.resolve("/get-notification-status"), BodyPublishers.ofString(jsonObject.toString()));
        return getData(getNotificationStatus).get("messages").getAsJsonArray();
    }

    /**
     * End the given test suite.
     */
    @SuppressWarnings("UnusedReturnValue")
    public boolean endTestSuite(final int testSuiteId) throws IOException, InterruptedException {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("testSuiteId", testSuiteId);

        final var endTestSuite =
            request(baseUrl.resolve("/end-test-suite"), BodyPublishers.ofString(jsonObject.toString()));
        return getData(endTestSuite).get("success").getAsBoolean();
    }

    /**
     * Perform HTTP request and return response.
     */
    protected String request(final URI uri) throws IOException, InterruptedException {
        return request(uri, BodyPublishers.noBody());
    }

    protected String request(final URI uri, final BodyPublisher bodyPublisher)
            throws IOException, InterruptedException {
        final var request = HttpRequest.newBuilder(uri)
            .POST(bodyPublisher)
            .build();

        final var response = HttpClient.newHttpClient().send(request, BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            JsonElement root = JsonParser.parseString(response.body());
            JsonObject error = root.getAsJsonObject().get("error").getAsJsonObject();

            String errorId = error.get("id").getAsString();
            String errorMessage = error.get("message").getAsString();

            throw new IllegalStateException("Error while requesting " + uri + " with body " + response.body() + " (" + errorId + ": " + errorMessage);
        }
        return response.body();
    }

    /**
     * Get a JSON object of the data in the JSON response.
     */
    protected static JsonObject getData(String response) {
        return JsonParser.parseString(response)
            .getAsJsonObject()
            .get("data")
            .getAsJsonObject();
    }
}

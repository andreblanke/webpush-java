package nl.martijndwars.webpush.selenium;

import java.security.GeneralSecurityException;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.junit.jupiter.api.function.Executable;

import nl.martijndwars.webpush.Notification;
import nl.martijndwars.webpush.PushService;
import nl.martijndwars.webpush.Subscription;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("SpellCheckingInspection")
public final class BrowserTest implements Executable {

    private final TestingService testingService;

    private final Configuration configuration;

    private final int testSuiteId;

    private static final String GCM_API_KEY = "AIzaSyBAU0VfXoskxUSg81K5VgLgwblHbZWe6tA";

    private static final String PUBLIC_KEY = "BNFDO1MUnNpx0SuQyQcAAWYETa2+W8z/uc5sxByf/UZLHwAhFLwEDxS5iB654KHiryq0AxDhFXS7DVqXDKjjN+8=";

    private static final String PRIVATE_KEY = "AM0aAyoIryzARADnIsSCwg1p1aWFAL3Idc8dNXpf74MH";

    private static final String VAPID_SUBJECT = "http://localhost:8090";

    public BrowserTest(final TestingService testingService, final Configuration configuration, final int testSuiteId) {
        this.configuration = configuration;
        this.testingService = testingService;
        this.testSuiteId = testSuiteId;
    }

    /**
     * Execute the test for the given browser configuration.
     */
    @Override
    public void execute() throws Throwable {
        final var pushService = getPushService();

        JsonObject test = testingService.getSubscription(testSuiteId, configuration);

        int testId = test.get("testId").getAsInt();

        Subscription subscription = new Gson().fromJson(test.get("subscription").getAsJsonObject(), Subscription.class);

        final var message = "Hëllö, world!";
        Notification notification = Notification.builder()
            .subscription(subscription)
            .payload(message)
            .build();

        final var response = pushService.send(notification);
        assertEquals(201, response.statusCode());

        JsonArray messages = testingService.getNotificationStatus(testSuiteId, testId);
        assertEquals(1, messages.size());
        assertEquals(new JsonPrimitive(message), messages.get(0));
    }

    private PushService getPushService() throws GeneralSecurityException {
        var builder = PushService.builder();
        if (configuration.isVapid()) {
            builder = builder.withVapidSubject(VAPID_SUBJECT)
                .withVapidPublicKey(PUBLIC_KEY)
                .withVapidPrivateKey(PRIVATE_KEY);
        } else {
            builder = builder.withGcmApiKey(GCM_API_KEY);
        }
        return builder.build();
    }

    /**
     * The name used by JUnit to display the test.
     */
    public String getDisplayName() {
        return "Browser " + configuration.browser() + ", version " + configuration.version() + ", vapid " + configuration.isVapid();
    }
}

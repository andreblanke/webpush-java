package nl.martijndwars.webpush;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.time.Duration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NotificationTest {

    private static final URI ENDPOINT = URI.create("https://the-url.co.uk");

    private static final String PUBLIC_KEY = "BGu3hOwCLOBfdMReXf7-SD2x5tKs_vPapOneyngBOnu6PgNYdgLPKFAodfBnG60MqkXC0McPFehN2Kyuh6TKm14=";

    private static final int oneDayDurationInSeconds = 86400;

    @BeforeAll
    public static void addSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testNotificationBuilder() throws GeneralSecurityException {
        final var notification = Notification.builder()
            .endpoint(ENDPOINT)
            .userPublicKey(PUBLIC_KEY)
            .payload(new byte[16])
            .ttl((int) Duration.ofDays(15).getSeconds())
            .build();
        assertEquals(ENDPOINT, notification.endpoint());
        assertEquals(15 * oneDayDurationInSeconds, notification.ttl());
    }

    @Test
    public void testDefaultTtl() throws GeneralSecurityException {
        final var notification = Notification.builder()
            .endpoint(ENDPOINT)
            .userPublicKey(PUBLIC_KEY)
            .payload(new byte[16])
            .build();
        assertEquals(28 * oneDayDurationInSeconds, notification.ttl());
    }
}

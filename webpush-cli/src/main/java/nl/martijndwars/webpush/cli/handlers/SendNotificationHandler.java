package nl.martijndwars.webpush.cli.handlers;

import java.net.http.HttpResponse;

import nl.martijndwars.webpush.Notification;
import nl.martijndwars.webpush.PushService;
import nl.martijndwars.webpush.Subscription;
import nl.martijndwars.webpush.cli.commands.SendNotificationCommand;

public class SendNotificationHandler implements HandlerInterface {

    private final SendNotificationCommand sendNotificationCommand;

    public SendNotificationHandler(SendNotificationCommand sendNotificationCommand) {
        this.sendNotificationCommand = sendNotificationCommand;
    }

    @Override
    public void run() throws Exception {
        final var pushService = PushService.builder()
            .withVapidPublicKey(sendNotificationCommand.getPublicKey())
            .withVapidPrivateKey(sendNotificationCommand.getPrivateKey())
            .withVapidSubject("mailto:admin@domain.com")
            .build();
        try (pushService) {
            Subscription subscription = sendNotificationCommand.getSubscription();

            final var notification = Notification.builder()
                .subscription(subscription)
                .payload(sendNotificationCommand.getPayload())
                .build();

            HttpResponse<?> response = pushService.send(notification);

            System.out.println(response);
        }
    }
}

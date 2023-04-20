package dev.blanke.webpush.cli.handlers;

import java.net.http.HttpResponse;

import dev.blanke.webpush.Notification;
import dev.blanke.webpush.PushService;
import dev.blanke.webpush.Subscription;
import dev.blanke.webpush.cli.commands.SendNotificationCommand;

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

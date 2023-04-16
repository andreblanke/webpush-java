package nl.martijndwars.webpush.cli.handlers;

import java.net.http.HttpClient;
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
        PushService pushService = new PushService(HttpClient.newHttpClient())
            .setPublicKey(sendNotificationCommand.getPublicKey())
            .setPrivateKey(sendNotificationCommand.getPrivateKey())
            .setSubject("mailto:admin@domain.com");

        Subscription subscription = sendNotificationCommand.getSubscription();

        Notification notification = Notification.builder()
            .subscription(subscription)
            .payload(sendNotificationCommand.getPayload())
            .build();

        HttpResponse<?> response = pushService.send(notification);

        System.out.println(response);
    }
}

package dev.blanke.webpush;

public record Subscription(String endpoint, Keys keys) {

    public record Keys(String p256dh, String auth) {}
}

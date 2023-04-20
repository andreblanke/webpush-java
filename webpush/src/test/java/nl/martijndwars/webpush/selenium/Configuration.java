package nl.martijndwars.webpush.selenium;

public record Configuration(String browser, String version, String publicKey, String gcmSenderId) {

    public boolean isVapid() {
        return (publicKey() != null) && !publicKey().isEmpty();
    }
}

module webpush {
    requires java.net.http;

    requires org.bouncycastle.provider;

    exports nl.martijndwars.webpush;
    exports nl.martijndwars.webpush.jwt;

    uses nl.martijndwars.webpush.jwt.JwtFactory;
}

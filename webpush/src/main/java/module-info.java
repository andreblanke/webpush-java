module webpush {
    requires java.net.http;

    requires at.favre.lib.hkdf;

    exports nl.martijndwars.webpush;
    exports nl.martijndwars.webpush.jwt;
    exports nl.martijndwars.webpush.util to webpush.cli;

    uses nl.martijndwars.webpush.jwt.JwtFactory;
}

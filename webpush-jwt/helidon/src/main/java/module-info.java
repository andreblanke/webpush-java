import nl.martijndwars.webpush.jwt.helidon.HelidonJwtFactory;

module webpush.jwt.helidon {
    requires webpush;

    requires io.helidon.security.jwt;

    provides nl.martijndwars.webpush.jwt.JwtFactory with HelidonJwtFactory;
}

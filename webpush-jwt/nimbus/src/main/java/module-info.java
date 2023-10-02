import nl.martijndwars.webpush.jwt.nimbus.NimbusJwtFactory;

module webpush.jwt.nimbus {
    requires webpush;

    requires com.nimbusds.jose.jwt;

    provides nl.martijndwars.webpush.jwt.JwtFactory with NimbusJwtFactory;
}

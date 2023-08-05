import nl.martijndwars.webpush.jwt.jose4j.Jose4jJwtFactory;

module webpush.jwt.jose4j {
    requires webpush;

    requires org.jose4j;

    provides nl.martijndwars.webpush.jwt.JwtFactory with Jose4jJwtFactory;
}

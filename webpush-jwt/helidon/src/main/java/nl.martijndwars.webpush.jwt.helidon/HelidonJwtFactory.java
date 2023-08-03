package nl.martijndwars.webpush.jwt.helidon;

import java.security.interfaces.ECPrivateKey;
import java.util.Map;

import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkEC;

import nl.martijndwars.webpush.jwt.JwtFactory;

@SuppressWarnings("unused")
public final class HelidonJwtFactory implements JwtFactory {

    @Override
    public String serialize(final Map<String, Object> headerClaims, final Map<String, Object> payloadClaims,
                            final ECPrivateKey vapidPrivateKey) {
        // TODO: Currently, the "upn" claim is if the "sub" claim is present with no option to disable this behavior.
        final var jwtBuilder = Jwt.builder();
        headerClaims.forEach(jwtBuilder::addHeaderClaim);
        payloadClaims.forEach(jwtBuilder::addPayloadClaim);

        /*
         * TODO: ES256 is the default algorithm chosen by JwkEC, but this should be made explicit. Currently, this is
         *       not possible via JwkEC.builder and JwkEC.create would have to be used instead, requiring a JsonObject.
         */
        final var signedJwt = SignedJwt.sign(jwtBuilder.build(), JwkEC.builder()
            .privateKey(vapidPrivateKey)
            .build());
        return signedJwt.tokenContent();
    }
}

package nl.martijndwars.webpush.jwt.nimbus;

import java.security.interfaces.ECPrivateKey;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import nl.martijndwars.webpush.jwt.JwtFactory;

public final class NimbusJwtFactory implements JwtFactory {

    @Override
    public String serialize(final Map<String, Object> headerClaims, final Map<String, Object> payloadClaims,
                            final ECPrivateKey vapidPrivateKey) {
        final var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .customParams(headerClaims)
            .build();

        final var jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        payloadClaims.forEach(jwtClaimsSetBuilder::claim);

        final var signedJwt = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        try {
            signedJwt.sign(new ECDSASigner(vapidPrivateKey));
        } catch (final JOSEException exception) {
            throw new RuntimeException(exception);
        }
        return signedJwt.serialize();
    }
}

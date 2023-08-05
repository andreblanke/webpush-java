package nl.martijndwars.webpush.jwt.jose4j;

import java.security.interfaces.ECPrivateKey;
import java.util.Map;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import nl.martijndwars.webpush.jwt.JwtFactory;

@SuppressWarnings("unused")
public final class JOSE4jJwtFactory implements JwtFactory {

    @Override
    public String serialize(final Map<String, Object> headerClaims, final Map<String, Object> payloadClaims,
                            final ECPrivateKey vapidPrivateKey) {
        try {
            final var claims = new JwtClaims();
            payloadClaims.forEach(claims::setClaim);

            final var jws = new JsonWebSignature();
            headerClaims.forEach(jws::setHeader);

            jws.setPayload(claims.toJson());
            jws.setKey(vapidPrivateKey);

            return jws.getCompactSerialization();
        } catch (final JoseException exception) {
            throw new RuntimeException(exception);
        }
    }
}

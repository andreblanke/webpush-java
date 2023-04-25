package nl.martijndwars.webpush.jwt;

import java.security.interfaces.ECPrivateKey;
import java.util.Map;

@FunctionalInterface
public interface JwtFactory {

    String serialize(Map<String, Object> headerClaims, Map<String, Object> payloadClaims, ECPrivateKey vapidPrivateKey);
}

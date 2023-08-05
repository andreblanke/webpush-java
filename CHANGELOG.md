# 6.1.0

* Rename `Jose4jJwtFactory` to `JOSE4jJwtFactory`
* Move `HelidonJwtFactory` and `JOSE4jJwtFactory` into separate artifacts, `dev.blanke.webpush:webpush-jwt-helidon` and
  `dev.blanke.webpush:webpush-jwt-jose4j`, respectively
    * Move implementations into `nl.martijndwars.webpush.jwt.{helidon,jose4j}` package to avoid split packages
* Use `ServiceLoader` to discover default `JwtFactory` implementation
    * Modularize library by adding `module-info.java` files to all artifacts
    * Add `META-INF/services/nl.martijndwars.webpush.jwt.JwtFactory` to discover `JwtFactory` implementations when the
      module path is not used
* Update `org.bouncycastle:bcprov-jdk18on` to version 1.76 fixing CVE-2023-33201

# 6.0.0

* Target Java 17
* No longer separate synchronous and asynchronous `PushService` implementations
* Use `java.net.http.HttpClient` for default `PushService` instead of an external dependency
* Introduce `JwtFactory` adapter interface to remove hard dependency on JOSE4j
* Separate CLI and library modules

# 5.1.1

* Target Java 8 instead of Java 7.
* Added an asynchronous version `PushAsyncService` of the `PushService` that performs non-blocking HTTP calls. Uses `async-http-client` under the hood.

# 5.1.0

* Improvement: Add support for [urgency](https://tools.ietf.org/html/rfc8030#section-5.3) & [topic](https://tools.ietf.org/html/rfc8030#section-5.4) (contributed by jamie@checkin.tech).
* Maintenance: Upgrade com.beust:jcommander to 1.78.
* Maintenance: Upgrade org.bitbucket.b\_c:jose4j to 0.7.0.

# 5.0.1

* Bugfix: Only verify the VAPID key pair if the keys are actually present (fixes #73).
* Improvement: Add test configurations for GCM-only to the selenium test suite.

# 5.0.0

* Use aes128gcm as the default encoding (#75).
* Remove BouncyCastle JAR from source and let Gradle put together the class path for the CLI.

# 4.0.0

* Support [aes128gcm content encoding](https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09#section-2) (#72)
  * Use `PushService.send(Notification, Encoding)` or the analogous `sendAsync` with `Encoding.AES128GCM`.
* Remove Guava dependency (#69)


package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.42
 */
public final class ClientAssertionKey {

    private final RSAKey key;

    private ClientAssertionKey(RSAKey key) {
        this.key = key;
    }

    public static ClientAssertionKey generate() {
        try {
            return new ClientAssertionKey(new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate the client assertion key", ex);
        }
    }

    /**
     * What the authorization server fetches from the client's {@code jwkSetUrl}. Only the public
     * half - the private key never leaves the client, which is the entire advantage over a shared
     * secret.
     */
    public String publicJwkSetJson() {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    public String keyId() {
        return key.getKeyID();
    }

    /**
     * Builds an RFC 7523 client assertion: the client proves who it is by signing a short-lived JWT
     * rather than by sending a password.
     *
     * @param audience the token endpoint - the authorization server checks this so an assertion
     *                 captured by one endpoint cannot be replayed against another
     * @param lifetime negative values produce an already-expired assertion, for the failing case
     */
    public String assertion(String clientId, String audience, Duration lifetime) {
        return assertion(clientId, audience, lifetime, this.key);
    }

    /**
     * Signs with a key the authorization server has never seen, standing in for an impostor that
     * knows the client id but not its key.
     */
    public String assertionSignedByAnotherKey(String clientId, String audience, Duration lifetime) {
        return assertion(clientId, audience, lifetime, generate().key);
    }

    private static String assertion(String clientId, String audience, Duration lifetime, RSAKey signingKey) {
        Instant now = Instant.now();
        try {
            SignedJWT assertion = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                    new JWTClaimsSet.Builder()
                            // iss and sub are both the client id: the client is asserting its own
                            // identity, not speaking for a user.
                            .issuer(clientId)
                            .subject(clientId)
                            .audience(List.of(audience))
                            .jwtID(UUID.randomUUID().toString())
                            .issueTime(Date.from(now))
                            .expirationTime(Date.from(now.plus(lifetime)))
                            .build());
            assertion.sign(new RSASSASigner(signingKey));
            return assertion.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the client assertion", ex);
        }
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.JOSEObjectType;
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
import java.util.Map;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.15
 */
public final class JarRequestSigner {

    /** RFC 9101 section 4: request objects are typed so they cannot be confused with other JWTs. */
    private static final JOSEObjectType OAUTH_AUTHZ_REQ = new JOSEObjectType("oauth-authz-req+jwt");

    private final RSAKey key;

    private JarRequestSigner(RSAKey key) {
        this.key = key;
    }

    public static JarRequestSigner generate() {
        try {
            return new JarRequestSigner(new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate the request object signing key", ex);
        }
    }

    /** Only the public half; the authorization server fetches this to check signatures. */
    public String publicJwkSetJson() {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    /**
     * Wraps the authorization request parameters in a signed JWT.
     *
     * @param issuerUri the authorization server, which becomes the audience - a request object
     *                  signed for one server cannot be replayed at another
     */
    public String sign(String clientId, String issuerUri, Map<String, String> parameters) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                // RFC 9101 section 4: the client is the issuer of its own request object.
                .issuer(clientId)
                .audience(List.of(issuerUri))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))));
        parameters.forEach(claims::claim);

        try {
            SignedJWT requestObject = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(OAUTH_AUTHZ_REQ).keyID(key.getKeyID()).build(),
                    claims.build());
            requestObject.sign(new RSASSASigner(key));
            return requestObject.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the request object", ex);
        }
    }

    /** Signed with a key the authorization server has never seen, for the failing case. */
    /**
     * RFC 9101 section 6.2: signed first, then encrypted to the authorization server. The order is
     * the same as JARM's and for the same reason - the signature has to be over what the server will
     * read, not over a blob it cannot see inside.
     *
     * @param serverKey the encryption key the authorization server publishes
     */
    public String signAndEncrypt(String clientId, String issuerUri, Map<String, String> parameters,
                                 RSAKey serverKey) {
        String signed = sign(clientId, issuerUri, parameters);
        return encrypt(signed, serverKey);
    }

    /** Wraps an already-signed request object for one recipient and nobody else. */
    public String encrypt(String signedRequestObject, RSAKey serverKey) {
        try {
            JWEObject encrypted = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                            .keyID(serverKey.getKeyID())
                            // So the server knows a JWT is inside rather than arbitrary bytes.
                            .contentType("JWT")
                            .build(),
                    new Payload(signedRequestObject));
            encrypted.encrypt(new RSAEncrypter(serverKey));
            return encrypted.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to encrypt the request object", ex);
        }
    }

    public String signWithAnotherKey(String clientId, String issuerUri, Map<String, String> parameters) {
        return generate().sign(clientId, issuerUri, parameters);
    }
}

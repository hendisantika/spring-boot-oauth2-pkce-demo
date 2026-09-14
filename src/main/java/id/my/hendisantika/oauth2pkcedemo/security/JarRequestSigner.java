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
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.PlainJWT;
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

    /**
     * A second key, on a curve rather than a modulus. Nothing here signs with it by default; it
     * exists so that a client can sign with an algorithm this server does not advertise, and so that
     * the refusal is about the algorithm rather than about a key the server never saw.
     */
    private final ECKey ellipticKey;

    private JarRequestSigner(RSAKey key, ECKey ellipticKey) {
        this.key = key;
        this.ellipticKey = ellipticKey;
    }

    public static JarRequestSigner generate() {
        try {
            return new JarRequestSigner(
                    new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate(),
                    new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate the request object signing key", ex);
        }
    }

    /** Only the public halves; the authorization server fetches these to check signatures. */
    public String publicJwkSetJson() {
        return new JWKSet(List.of(key.toPublicJWK(), ellipticKey.toPublicJWK())).toString();
    }

    /**
     * The same object signed on the curve. ES256 is a perfectly ordinary JWS algorithm that this
     * server does not list as one it checks request objects with, which is the only reason this
     * exists.
     */
    public String signWithEllipticCurve(String clientId, String issuerUri,
                                        Map<String, String> parameters) {
        try {
            SignedJWT requestObject = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).type(OAUTH_AUTHZ_REQ)
                            .keyID(ellipticKey.getKeyID()).build(),
                    claims(clientId, issuerUri, parameters));
            requestObject.sign(new ECDSASigner(ellipticKey));
            return requestObject.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the request object", ex);
        }
    }

    /**
     * Wraps the authorization request parameters in a signed JWT.
     *
     * @param issuerUri the authorization server, which becomes the audience - a request object
     *                  signed for one server cannot be replayed at another
     */
    public String sign(String clientId, String issuerUri, Map<String, String> parameters) {
        return sign(clientId, issuerUri, parameters, JWSAlgorithm.RS256);
    }

    /**
     * The same object signed with a named algorithm. One RSA key can carry either RS256 or PS256 -
     * they differ in the padding, not in the key - which is what makes the registered algorithm a
     * choice a client could otherwise change from one request to the next.
     */
    public String sign(String clientId, String issuerUri, Map<String, String> parameters,
                       JWSAlgorithm algorithm) {
        try {
            SignedJWT requestObject = new SignedJWT(
                    new JWSHeader.Builder(algorithm).type(OAUTH_AUTHZ_REQ).keyID(key.getKeyID()).build(),
                    claims(clientId, issuerUri, parameters));
            requestObject.sign(new RSASSASigner(key));
            return requestObject.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the request object", ex);
        }
    }

    /**
     * A request object with {@code alg: none} and no signature at all. RFC 9101 section 4 reads as
     * though this cannot exist - the claims are "signed or signed and encrypted" - and then section
     * 10.5 defines a switch for refusing it, and OpenID Connect Dynamic Client Registration says
     * outright that "the value none MAY be used". So it exists, and a client may register for it.
     */
    public String unsigned(String clientId, String issuerUri, Map<String, String> parameters) {
        return new PlainJWT(new PlainHeader.Builder().type(OAUTH_AUTHZ_REQ).build(),
                claims(clientId, issuerUri, parameters)).serialize();
    }

    private static JWTClaimsSet claims(String clientId, String issuerUri,
                                       Map<String, String> parameters) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                // RFC 9101 section 4: the client is the issuer of its own request object.
                .issuer(clientId)
                .audience(List.of(issuerUri))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))));
        parameters.forEach(claims::claim);
        return claims.build();
    }

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
        return encrypt(signedRequestObject, serverKey, JWEAlgorithm.RSA_OAEP_256);
    }

    /**
     * The same wrapping with a named key-management algorithm. All of these wrap the same content
     * encryption key with the same RSA key and differ only in how - which is what makes the
     * registered algorithm a choice a client could otherwise change from one request to the next.
     */
    public String encrypt(String signedRequestObject, RSAKey serverKey, JWEAlgorithm algorithm) {
        return encrypt(signedRequestObject, serverKey, algorithm, EncryptionMethod.A128CBC_HS256);
    }

    /**
     * The two halves named separately. The {@code alg} decides how the content encryption key
     * travels; the {@code enc} decides what that key then does to the payload - and they are chosen,
     * and registered, independently.
     */
    public String encrypt(String signedRequestObject, RSAKey serverKey, JWEAlgorithm algorithm,
                          EncryptionMethod method) {
        try {
            JWEObject encrypted = new JWEObject(
                    new JWEHeader.Builder(algorithm, method)
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

    /** Signed with a key the authorization server has never seen, for the failing case. */
    public String signWithAnotherKey(String clientId, String issuerUri, Map<String, String> parameters) {
        return generate().sign(clientId, issuerUri, parameters);
    }
}

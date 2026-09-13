package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.24
 */
public final class DpopKeyPair {

    /** RFC 9449 section 4.2: proofs carry this type so they cannot be confused with other JWTs. */
    private static final JOSEObjectType DPOP_JWT = new JOSEObjectType("dpop+jwt");

    private final ECKey key;

    private DpopKeyPair(ECKey key) {
        this.key = key;
    }

    public static DpopKeyPair generate() {
        try {
            return new DpopKeyPair(new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate a DPoP key pair", ex);
        }
    }

    /**
     * The thumbprint the authorization server binds the token to, and the value that turns up as
     * {@code cnf.jkt} inside it.
     */
    public String thumbprint() {
        try {
            return key.toPublicJWK().computeThumbprint().toString();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to compute the JWK thumbprint", ex);
        }
    }

    public String publicJwkJson() {
        return key.toPublicJWK().toJSONString();
    }

    /**
     * Builds a proof for one specific request. The public key travels in the header, so the server
     * can check the signature and then compare the key's thumbprint with the one bound to the token.
     *
     * @param accessToken when present, its hash is included as {@code ath}, tying the proof to that
     *                    exact token rather than just to the key
     */
    public String proof(String httpMethod, String httpUri, String accessToken) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", httpMethod)
                    .claim("htu", httpUri)
                    .issueTime(Date.from(Instant.now()));
            if (accessToken != null) {
                claims.claim("ath", accessTokenHash(accessToken));
            }

            SignedJWT proof = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(DPOP_JWT)
                            .jwk(key.toPublicJWK())
                            .build(),
                    claims.build());
            proof.sign(new ECDSASigner(key));
            return proof.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the DPoP proof", ex);
        }
    }

    private static String accessTokenHash(String accessToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}

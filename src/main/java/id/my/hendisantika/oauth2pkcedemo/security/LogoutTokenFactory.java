package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
public final class LogoutTokenFactory {

    /** OpenID Connect Back-Channel Logout section 2.4: a logout token says so in its type. */
    public static final JOSEObjectType LOGOUT_JWT = new JOSEObjectType("logout+jwt");

    /** Section 2.4 again: the event that makes this a logout token rather than any other JWT. */
    public static final String BACK_CHANNEL_LOGOUT_EVENT =
            "http://schemas.openid.net/event/backchannel-logout";

    public static final String EVENTS = "events";

    private final JWKSource<SecurityContext> jwkSource;

    public LogoutTokenFactory(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    /** Signed with the key this server publishes, which is what a client will look the key up by. */
    public String sign(Map<String, Object> claims) {
        return sign(claims, serverKey());
    }

    /**
     * Signed with a key nobody can look up, for the attempt that has to fail. Everything else about
     * the token is correct, which is the point: a logout token is only worth what its signature is.
     */
    public String signWithAnotherKey(Map<String, Object> claims) {
        try {
            return sign(claims, new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate a foreign signing key", ex);
        }
    }

    private static String sign(Map<String, Object> claims, RSAKey key) {
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
        claims.forEach(claimsSet::claim);
        try {
            SignedJWT logoutToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(LOGOUT_JWT)
                            .keyID(key.getKeyID())
                            .build(),
                    claimsSet.build());
            logoutToken.sign(new RSASSASigner(key));
            return logoutToken.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to sign the logout token", ex);
        }
    }

    /** The same key the ID tokens were signed with, taken from the server's own JWK source. */
    private RSAKey serverKey() {
        try {
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
                    .keyType(KeyType.RSA)
                    .keyUses(KeyUse.SIGNATURE, null)
                    .build());
            return (RSAKey) this.jwkSource.get(selector, null).get(0);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to read the server's signing key", ex);
        }
    }
}

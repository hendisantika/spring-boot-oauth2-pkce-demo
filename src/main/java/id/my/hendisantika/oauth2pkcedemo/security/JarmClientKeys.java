package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.extern.slf4j.Slf4j;

import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 17.05
 */
@Slf4j
public final class JarmClientKeys {

    private final RSAKey key;

    private JarmClientKeys(RSAKey key) {
        this.key = key;
    }

    /**
     * A key pair belonging to the <em>client</em>, not the server. Encryption runs the other way
     * round from signing: the authorization server encrypts to a key only the client can undo, so
     * the client is the one that has to publish something.
     */
    public static JarmClientKeys generate() {
        try {
            return new JarmClientKeys(new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.ENCRYPTION)
                    .keyID(UUID.randomUUID().toString())
                    .generate());
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate the client's encryption key", ex);
        }
    }

    /** Only the public half, which is all the authorization server needs to encrypt to it. */
    public String publicJwkSetJson() {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    public String keyId() {
        return key.getKeyID();
    }

    /** What the client does on receiving one: undo the encryption and find a signed JWT inside. */
    public String decrypt(String jwe) {
        try {
            JWEObject encrypted = JWEObject.parse(jwe);
            encrypted.decrypt(new RSADecrypter(key));
            return encrypted.getPayload().toString();
        } catch (Exception ex) {
            log.debug("Unable to decrypt the authorization response: {}", ex.getMessage());
            throw new IllegalStateException("Unable to decrypt the authorization response", ex);
        }
    }
}

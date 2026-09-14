package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 14.20
 */
public record JarmAlgorithmAttempt(String clientId,
                                   String registeredAs,
                                   String resolvedTo,
                                   String headerAlgorithm,
                                   String keyId,
                                   boolean signed,
                                   Boolean signatureVerifies,
                                   String error) implements Serializable {

    /** Whether the client got what its registration promised it would. */
    public boolean isHonoured() {
        return signed && Boolean.TRUE.equals(signatureVerifies)
                && headerAlgorithm != null && headerAlgorithm.equals(resolvedTo);
    }
}

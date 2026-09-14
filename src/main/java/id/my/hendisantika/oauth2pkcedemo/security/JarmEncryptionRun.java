package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 17.05
 */
public record JarmEncryptionRun(String signedOnlyClientId,
                                String encryptedClientId,
                                String clientKeyId,
                                List<String> readableFromTheSignedResponse,
                                String signedResponse,
                                String encryptedResponse,
                                Map<String, Object> encryptionHeader,
                                String nestedSignedJwt,
                                Map<String, Object> claims,
                                boolean signatureVerifies,
                                Instant ranAt) implements Serializable {

    /** A JWS has three parts and a JWE has five; counting them is the quickest way to tell. */
    public int encryptedParts() {
        return encryptedResponse == null ? 0 : encryptedResponse.split("\\.").length;
    }

    public int signedParts() {
        return signedResponse == null ? 0 : signedResponse.split("\\.").length;
    }
}

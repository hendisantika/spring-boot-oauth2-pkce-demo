package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 20.40
 */
public record JarmEncryptionMethodAttempt(String clientId,
                                          String registeredAs,
                                          String resolvedTo,
                                          String headerMethod,
                                          int encryptedKeyChars,
                                          int ivChars,
                                          int ciphertextChars,
                                          int tagChars,
                                          int plaintextChars,
                                          boolean encrypted,
                                          String error) implements Serializable {

    /**
     * CBC pads the payload up to a block boundary; GCM does not, so its ciphertext is exactly as
     * long as what went in. Measuring is the only way to see the difference from outside.
     */
    public int overhead() {
        return encrypted ? ciphertextBytes() - plaintextChars : 0;
    }

    /** Base64url without padding: four characters carry three bytes. */
    public int ciphertextBytes() {
        return ciphertextChars * 3 / 4;
    }

    public int ivBytes() {
        return ivChars * 3 / 4;
    }

    public int tagBytes() {
        return tagChars * 3 / 4;
    }
}

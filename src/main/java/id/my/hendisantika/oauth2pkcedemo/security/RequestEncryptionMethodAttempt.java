package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 12.05
 */
public record RequestEncryptionMethodAttempt(String label,
                                             String clientId,
                                             String registeredEnc,
                                             String resolvedEnc,
                                             String sentEnc,
                                             int ivChars,
                                             int ciphertextChars,
                                             int tagChars,
                                             int plaintextChars,
                                             boolean accepted,
                                             String outcome) implements Serializable {

    /** What a client that registered no method at all reports in the registration column. */
    public static final String NOTHING_REGISTERED = "nothing";

    /** Whether what was sent is what the registration resolves to, the default included. */
    public boolean matchesRegistration() {
        return sentEnc.equals(resolvedEnc);
    }

    /**
     * CBC pads the payload up to a block boundary; GCM does not, so its ciphertext is exactly as
     * long as what went in. Measuring is the only way to see the difference from outside.
     */
    public int overhead() {
        return ciphertextBytes() - plaintextChars;
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

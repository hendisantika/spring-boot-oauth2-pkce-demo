package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 18/09/26
 * Time: 20.25
 */
public record EncryptionAlgValuesAttempt(String label,
                                         String description,
                                         String clientId,
                                         String registeredAlg,
                                         String sentAlg,
                                         boolean advertised,
                                         String keyUse,
                                         String keyId,
                                         boolean accepted,
                                         String outcome) implements Serializable {

    /** Whether the algorithm was the one this client agreed to use. */
    public boolean itsOwnAlgorithm() {
        return sentAlg.equals(registeredAlg);
    }

    /** Whether it was wrapped to the key the document marks for encryption. */
    public boolean toTheEncryptionKey() {
        return "enc".equals(keyUse);
    }

    /** Enough of the key id to tell one published key from another. */
    public String shortKeyId() {
        return keyId.length() <= 12 ? keyId : keyId.substring(0, 12) + "…";
    }
}

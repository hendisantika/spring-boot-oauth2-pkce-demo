package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 09.20
 */
public record RequestEncryptionAlgAttempt(String label,
                                          String clientId,
                                          String registeredAlg,
                                          String sentAlg,
                                          boolean accepted,
                                          String outcome) implements Serializable {

    /** What a request object that was not encrypted at all reports in the algorithm column. */
    public static final String NOT_ENCRYPTED = "—";

    /** Whether anything was wrapped at all. */
    public boolean encrypted() {
        return !NOT_ENCRYPTED.equals(sentAlg);
    }

    /** Whether what was sent is what the registration said would be sent. */
    public boolean matchesRegistration() {
        return sentAlg.equals(registeredAlg);
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 06.10
 */
public record SigningAlgAttempt(String label,
                                String clientId,
                                String registeredAlg,
                                String sentAlg,
                                boolean accepted,
                                String outcome) implements Serializable {

    /** Whether what was sent is what the registration said would be sent. */
    public boolean matchesRegistration() {
        return sentAlg.equals(registeredAlg);
    }
}

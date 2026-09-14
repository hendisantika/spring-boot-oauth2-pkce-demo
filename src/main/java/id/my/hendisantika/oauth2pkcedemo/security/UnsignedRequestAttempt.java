package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 14.30
 */
public record UnsignedRequestAttempt(String label,
                                     String description,
                                     String clientId,
                                     String registeredAlg,
                                     String sentAlg,
                                     boolean requireSignedRegistered,
                                     boolean encrypted,
                                     boolean accepted,
                                     String outcome) implements Serializable {

    /** Whether anything about this object could be checked against a key at all. */
    public boolean signed() {
        return !JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE.equals(sentAlg);
    }

    /** Whether what was sent is what the registration said would be sent. */
    public boolean matchesRegistration() {
        return sentAlg.equals(registeredAlg);
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 18/09/26
 * Time: 15.10
 */
public record AdvertisedAlgAttempt(String label,
                                   String description,
                                   String clientId,
                                   String registeredAlg,
                                   String sentAlg,
                                   boolean advertised,
                                   boolean accepted,
                                   String outcome) implements Serializable {

    /** Whether the client was using the algorithm it registered, whatever the server advertises. */
    public boolean itsOwnAlgorithm() {
        return sentAlg.equals(registeredAlg);
    }
}

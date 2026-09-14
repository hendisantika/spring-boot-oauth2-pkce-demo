package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 08.15
 */
public record ServerParRequiredAttempt(String label,
                                       String description,
                                       String clientId,
                                       boolean clientRequiresPar,
                                       String carried,
                                       boolean acceptedWhenOff,
                                       String outcomeWhenOff,
                                       boolean acceptedWhenOn,
                                       String outcomeWhenOn) implements Serializable {

    /** The rows worth reading twice: the switch is what changed the answer. */
    public boolean changedWithTheSwitch() {
        return acceptedWhenOff != acceptedWhenOn;
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 15.10
 */
public record FreshnessAttempt(String label,
                               String parameter,
                               long sessionAgeSeconds,
                               boolean sentBackThroughLogin,
                               Instant authTime,
                               Instant previousAuthTime,
                               String outcome) implements Serializable {

    /** The only proof that an authentication actually happened rather than being claimed. */
    public boolean movedAuthTime() {
        return authTime != null && previousAuthTime != null && authTime.isAfter(previousAuthTime);
    }

    /** A parameter asking for a new authentication that got none. */
    public boolean wasIgnored() {
        return !sentBackThroughLogin && !movedAuthTime();
    }
}

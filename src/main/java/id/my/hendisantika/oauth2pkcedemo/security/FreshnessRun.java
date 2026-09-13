package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 15.10
 */
public record FreshnessRun(String clientId,
                           String username,
                           Instant signedInAt,
                           List<FreshnessAttempt> attempts,
                           Instant ranAt) implements Serializable {

    /** How many of the asks that wanted a new authentication were answered with one. */
    public long honoured() {
        return attempts.stream().filter(FreshnessAttempt::sentBackThroughLogin).count();
    }
}

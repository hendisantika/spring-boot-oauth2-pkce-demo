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
 * Date: 15/09/26
 * Time: 11.30
 */
public record JarmRun(String clientId,
                      List<JarmAttempt> attempts,
                      Instant ranAt) implements Serializable {

    /** How many answers arrived as something the client can check rather than merely read. */
    public long signed() {
        return attempts.stream().filter(JarmAttempt::signed).count();
    }
}

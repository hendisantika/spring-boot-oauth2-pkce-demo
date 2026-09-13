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
 * Time: 17.20
 */
public record SilentAuthRun(String clientId,
                            List<SilentAuthAttempt> attempts,
                            Instant ranAt) implements Serializable {

    /** Every answer should be one the client can read; a screen would mean the parameter failed. */
    public boolean everythingStayedSilent() {
        return attempts.stream().allMatch(SilentAuthAttempt::isSilent);
    }
}

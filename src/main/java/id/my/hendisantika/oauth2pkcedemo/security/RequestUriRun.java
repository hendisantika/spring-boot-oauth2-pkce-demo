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
 * Time: 19.05
 */
public record RequestUriRun(String clientId,
                            String requestUri,
                            String randomPart,
                            Instant expiresAt,
                            long expiresInSeconds,
                            List<RequestUriAttempt> attempts,
                            Instant ranAt) implements Serializable {

    /** Only the first use of a pushed request should ever produce anything. */
    public long uses() {
        return attempts.stream().filter(RequestUriAttempt::gotCode).count();
    }
}

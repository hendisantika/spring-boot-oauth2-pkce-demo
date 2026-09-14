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
 * Time: 23.40
 */
public record RequestObjectRun(String clientId,
                               String serverKeyId,
                               String loginHint,
                               List<RequestObjectAttempt> attempts,
                               Instant ranAt) implements Serializable {

    /** Both well-formed requests should be acted on; the wrongly addressed one should not. */
    public long accepted() {
        return attempts.stream().filter(RequestObjectAttempt::accepted).count();
    }
}

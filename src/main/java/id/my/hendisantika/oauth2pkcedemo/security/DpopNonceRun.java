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
 * Time: 23.05
 */
public record DpopNonceRun(String clientId,
                           String thumbprint,
                           String boundTo,
                           List<DpopNonceAttempt> attempts,
                           Instant ranAt) implements Serializable {

    /** Only a call whose proof echoes a nonce this server issued should get through. */
    public long accepted() {
        return attempts.stream().filter(DpopNonceAttempt::isAccepted).count();
    }
}

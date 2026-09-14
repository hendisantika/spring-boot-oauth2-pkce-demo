package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 21.10
 */
public record RarEnforcementRun(String clientId,
                                List<Map<String, Object>> grantedDetails,
                                List<RarEnforcementAttempt> attempts,
                                Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(RarEnforcementAttempt::isAccepted).count();
    }
}

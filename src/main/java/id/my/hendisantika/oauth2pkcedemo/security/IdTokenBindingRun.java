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
 * Time: 11.05
 */
public record IdTokenBindingRun(Map<String, Object> claims,
                                String subject,
                                String atHashOfIssuedToken,
                                String atHashOfOtherToken,
                                String otherTokenSubject,
                                boolean carriesAtHash,
                                boolean carriesConfirmation,
                                List<IdTokenCheck> checks,
                                Instant ranAt) implements Serializable {

    /** How many substitutions went unnoticed, which is what the page is really counting. */
    public long gaps() {
        return checks.stream().filter(IdTokenCheck::isGap).count();
    }
}

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
 * Date: 15/09/26
 * Time: 14.20
 */
public record JarmAlgorithmRun(List<JarmAlgorithmAttempt> attempts,
                               Map<String, String> publishedKeys,
                               Instant ranAt) implements Serializable {

    /** A registration this server cannot honour should be refused rather than quietly downgraded. */
    public long refused() {
        return attempts.stream().filter(attempt -> !attempt.signed()).count();
    }
}

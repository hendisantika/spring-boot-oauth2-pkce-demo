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
 * Date: 17/09/26
 * Time: 08.15
 */
public record ServerParRequiredRun(String publishedWhenOff,
                                   String publishedWhenOn,
                                   String fapiRowWhenOff,
                                   String fapiRowWhenOn,
                                   boolean restoredAfterwards,
                                   List<ServerParRequiredAttempt> attempts,
                                   Instant ranAt) implements Serializable {

    /** What the documents said tracked the switch, which is what makes it server metadata. */
    public boolean metadataFollowedTheSwitch() {
        return "false".equals(publishedWhenOff) && "true".equals(publishedWhenOn);
    }

    /** A pushed request is unaffected: the switch removes ways of asking, it does not add checks. */
    public boolean everyPushedRowSurvivedBothSettings() {
        return attempts.stream()
                .filter(attempt -> attempt.carried().contains("request_uri"))
                .allMatch(attempt -> attempt.acceptedWhenOff() && attempt.acceptedWhenOn());
    }

    /** And the profile row went with it, which is the point of checking configuration not intent. */
    public boolean theProfileRowFollowedTheSwitch() {
        return "FAIL".equals(fapiRowWhenOff) && "PASS".equals(fapiRowWhenOn);
    }

    public long changedWithTheSwitch() {
        return attempts.stream().filter(ServerParRequiredAttempt::changedWithTheSwitch).count();
    }
}

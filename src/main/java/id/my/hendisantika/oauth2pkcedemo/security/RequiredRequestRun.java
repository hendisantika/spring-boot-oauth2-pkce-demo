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
 * Date: 16/09/26
 * Time: 17.20
 */
public record RequiredRequestRun(String publishedWhenOff,
                                 String publishedWhenOn,
                                 boolean restoredAfterwards,
                                 List<RequiredRequestAttempt> attempts,
                                 Instant ranAt) implements Serializable {

    /** What the documents said tracked the switch, which is what makes it server metadata. */
    public boolean metadataFollowedTheSwitch() {
        return "false".equals(publishedWhenOff) && "true".equals(publishedWhenOn);
    }

    /** A signed request object is unaffected: the switch removes choices, it does not add checks. */
    public boolean everySignedRowSurvivedBothSettings() {
        return attempts.stream()
                .filter(attempt -> attempt.sent().contains("Signed"))
                .allMatch(attempt -> attempt.acceptedWhenOff() && attempt.acceptedWhenOn());
    }

    public long changedWithTheSwitch() {
        return attempts.stream().filter(RequiredRequestAttempt::changedWithTheSwitch).count();
    }
}

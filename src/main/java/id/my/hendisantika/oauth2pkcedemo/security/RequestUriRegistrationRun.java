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
 * Time: 21.30
 */
public record RequestUriRegistrationRun(String clientId,
                                        List<String> registeredUris,
                                        String publishedWhenRequired,
                                        String publishedWhenNotRequired,
                                        boolean restoredAfterwards,
                                        List<RequestUriRegistrationAttempt> attempts,
                                        Instant ranAt) implements Serializable {

    /** What the documents said tracked the setting, which is what makes it metadata. */
    public boolean metadataFollowedTheSetting() {
        return "true".equals(publishedWhenRequired) && "false".equals(publishedWhenNotRequired);
    }

    /** Everything registered was fetched under both settings: the list is not the only check. */
    public boolean theRegisteredUrlWorkedBothWays() {
        return attempts.stream()
                .filter(RequestUriRegistrationAttempt::registeredForThisClient)
                .anyMatch(attempt -> attempt.acceptedWhenRequired()
                        && attempt.acceptedWhenNotRequired());
    }

    /** And the other checks refused the same things either way, which is the point of having them. */
    public long refusedUnderBothSettings() {
        return attempts.stream()
                .filter(attempt -> !attempt.acceptedWhenRequired()
                        && !attempt.acceptedWhenNotRequired())
                .count();
    }
}

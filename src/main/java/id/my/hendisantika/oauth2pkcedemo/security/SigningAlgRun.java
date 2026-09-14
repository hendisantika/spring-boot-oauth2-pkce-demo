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
 * Time: 06.10
 */
public record SigningAlgRun(String defaultAlg,
                            List<String> supportedAlgs,
                            List<SigningAlgAttempt> attempts,
                            Instant ranAt) implements Serializable {

    /** Two rows send what their client registered; nothing else should have been acted on. */
    public long accepted() {
        return attempts.stream().filter(SigningAlgAttempt::accepted).count();
    }

    /** The claim the page is making: accepted exactly when the algorithm matched the registration. */
    public boolean acceptedOnlyWhenRegistered() {
        return attempts.stream()
                .allMatch(attempt -> attempt.accepted() == attempt.matchesRegistration());
    }
}

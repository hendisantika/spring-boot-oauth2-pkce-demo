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
 * Date: 18/09/26
 * Time: 15.10
 */
public record AdvertisedAlgRun(Map<String, Object> published,
                               List<AdvertisedAlgAttempt> attempts,
                               Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(AdvertisedAlgAttempt::accepted).count();
    }

    /** Nothing off the advertised list was acted on: the list is not decoration. */
    public boolean nothingUnadvertisedWasAccepted() {
        return attempts.stream().noneMatch(attempt -> attempt.accepted() && !attempt.advertised());
    }

    /**
     * And being on the list was not enough either. The claim the page is making: a request object was
     * acted on exactly when its algorithm was both advertised by the server and registered by the
     * client sending it.
     */
    public boolean acceptedExactlyWhenAdvertisedAndRegistered() {
        return attempts.stream().allMatch(attempt ->
                attempt.accepted() == (attempt.advertised() && attempt.itsOwnAlgorithm()));
    }
}

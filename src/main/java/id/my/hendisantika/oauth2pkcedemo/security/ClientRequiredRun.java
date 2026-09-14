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
 * Date: 16/09/26
 * Time: 20.05
 */
public record ClientRequiredRun(String lockedClientId,
                                String contradictoryClientId,
                                Map<String, Object> lockedRegistrationResponse,
                                boolean serverRequiresSignedRequestObjects,
                                List<ClientRequiredAttempt> attempts,
                                Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(ClientRequiredAttempt::accepted).count();
    }

    /** The registration response echoed what was asked for, so the caller can confirm it took. */
    public boolean registrationEchoedTheSetting() {
        Object echoed = lockedRegistrationResponse
                .get(RequestObjectClientRegistrationConverters.REQUIRE_SIGNED_REQUEST_OBJECT);
        return Boolean.parseBoolean(String.valueOf(echoed));
    }

    /** The control client's ordinary request works, so nothing here is the server-wide switch. */
    public boolean theUnlockedClientWasLeftAlone() {
        return attempts.stream()
                .filter(attempt -> attempt.label().startsWith("An ordinary request, from a client"))
                .allMatch(ClientRequiredAttempt::accepted);
    }

    /** Nothing the contradictory client can send is acceptable, which is the point of that pair. */
    public boolean theContradictoryClientCanSendNothing() {
        return attempts.stream()
                .filter(attempt -> attempt.clientId().equals(contradictoryClientId))
                .noneMatch(ClientRequiredAttempt::accepted);
    }
}

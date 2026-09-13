package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
public record BackChannelLogoutRun(String clientName,
                                   String backChannelUri,
                                   String logoutToken,
                                   Map<String, Object> logoutTokenClaims,
                                   List<BackChannelAttempt> attempts,
                                   boolean sessionInvalidated,
                                   Instant ranAt) implements Serializable {

    public BackChannelLogoutRun {
        logoutTokenClaims = new TreeMap<>(logoutTokenClaims);
    }

    /**
     * Whether the one request that should have worked did. The browser was not involved in it at
     * all, which is the whole difference between this and the logout with a redirect.
     */
    public boolean accepted() {
        return attempts.stream().anyMatch(BackChannelAttempt::isSuccess);
    }
}

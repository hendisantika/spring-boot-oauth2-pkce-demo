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
 * Date: 13/09/26
 * Time: 21.06
 */
public record RefreshBindingRun(String clientId,
                                String thumbprint,
                                String accessTokenConfirmation,
                                String tokenType,
                                boolean refreshTokenIssued,
                                List<RefreshBindingAttempt> attempts,
                                Instant ranAt) implements Serializable {

    /**
     * Whether a refresh request that brought no proof at all was served anyway. RFC 9449 section 5
     * says a public client's refresh token is bound to the key; if this is true, it is not.
     */
    public boolean servedWithoutAProof() {
        return attempts.stream().anyMatch(RefreshBindingAttempt::unbound);
    }
}

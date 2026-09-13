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
 * Time: 19.42
 */
public record LogoutRevocationRun(boolean revoked,
                                  String clientName,
                                  List<LogoutStep> steps,
                                  boolean accessTokenSurvived,
                                  boolean refreshTokenMintedAnother,
                                  Instant ranAt) implements Serializable {

    /**
     * Whether signing out actually ended the user's access. It did not, unless something revoked -
     * which is the entire finding.
     */
    public boolean sessionEndedButAccessDidNot() {
        return accessTokenSurvived || refreshTokenMintedAnother;
    }
}

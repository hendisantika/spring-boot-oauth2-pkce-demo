package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.56
 */
public record RevocationResult(String tokenType,
                               int statusCode,
                               String error,
                               Instant revokedAt) implements Serializable {

    public boolean isAccepted() {
        // RFC 7009 section 2.2: the endpoint answers 200 whether or not the token existed, so a
        // client cannot use it to probe which tokens are real.
        return statusCode == 200;
    }
}

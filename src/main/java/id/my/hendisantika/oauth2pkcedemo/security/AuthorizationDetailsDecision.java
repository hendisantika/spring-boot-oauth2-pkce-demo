package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 21.10
 */
public record AuthorizationDetailsDecision(boolean allowed, String reason) implements Serializable {

    public static AuthorizationDetailsDecision allowed(String reason) {
        return new AuthorizationDetailsDecision(true, reason);
    }

    public static AuthorizationDetailsDecision refused(String reason) {
        return new AuthorizationDetailsDecision(false, reason);
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.42
 */
public record ClientAssertionAttempt(String label,
                                     String description,
                                     Map<String, Object> assertionClaims,
                                     int statusCode,
                                     String body) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }
}

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
public record RarEnforcementAttempt(String label,
                                    String instruction,
                                    String tokenDescription,
                                    int statusCode,
                                    String reason) implements Serializable {

    public boolean isAccepted() {
        return statusCode == 200;
    }
}

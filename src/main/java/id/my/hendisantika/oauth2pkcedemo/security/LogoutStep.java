package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.42
 */
public record LogoutStep(String label,
                         String description,
                         String outcome,
                         boolean tokenUsable) implements Serializable {

    public static LogoutStep of(String label, String description, String outcome, boolean tokenUsable) {
        return new LogoutStep(label, description, outcome, tokenUsable);
    }
}

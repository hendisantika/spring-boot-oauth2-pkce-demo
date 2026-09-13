package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
public record BackChannelAttempt(String label,
                                 String description,
                                 int statusCode,
                                 String outcome) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.02
 */
public record MtlsAttempt(String label,
                          String description,
                          int statusCode,
                          String outcome,
                          String boundThumbprint) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 09.12
 */
public record MtlsRefreshAttempt(String label,
                                 String description,
                                 int statusCode,
                                 String confirmation,
                                 String outcome) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }
}

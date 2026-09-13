package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
public record FrontChannelProbe(String label,
                                String description,
                                int statusCode,
                                String outcome) implements Serializable {

    /** Nothing answered at all, which the server that rendered the iframe also cannot see. */
    public boolean unreachable() {
        return statusCode == 0;
    }
}

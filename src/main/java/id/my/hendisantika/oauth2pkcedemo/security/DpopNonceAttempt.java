package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 23.05
 */
public record DpopNonceAttempt(String label,
                               String nonceSent,
                               int statusCode,
                               String error,
                               String challenge,
                               String nonceGivenBack) implements Serializable {

    public boolean isAccepted() {
        return statusCode == 200;
    }

    public String outcome() {
        return isAccepted() ? "200" : (error == null ? String.valueOf(statusCode) : error);
    }
}

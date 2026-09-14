package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 19.05
 */
public record RequestUriAttempt(String label,
                                String description,
                                int statusCode,
                                boolean gotCode,
                                boolean reachedTheClient,
                                String error,
                                boolean stillStored) implements Serializable {

    public String outcome() {
        if (gotCode) {
            return "code";
        }
        return error == null ? String.valueOf(statusCode) : error;
    }

    /** Whether the answer went where a client could read it, rather than onto the screen. */
    public boolean isAnsweredToTheClient() {
        return reachedTheClient;
    }
}

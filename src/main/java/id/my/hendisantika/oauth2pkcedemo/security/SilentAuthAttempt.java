package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 17.20
 */
public record SilentAuthAttempt(String label,
                                String request,
                                String state,
                                String error,
                                String errorDescription,
                                boolean gotCode,
                                boolean sawAScreen) implements Serializable {

    /** An answer the client can act on without the user ever seeing anything. */
    public boolean isSilent() {
        return !sawAScreen;
    }

    public String outcome() {
        if (sawAScreen) {
            return "a screen";
        }
        return gotCode ? "code" : String.valueOf(error);
    }
}

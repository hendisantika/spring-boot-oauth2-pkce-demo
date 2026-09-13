package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 21.06
 */
public record RefreshBindingAttempt(String label,
                                    String description,
                                    int statusCode,
                                    String tokenType,
                                    String confirmation,
                                    String outcome) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }

    /** A token that came back still tied to the key, which is what the exchange is supposed to keep. */
    public boolean stillBound() {
        return isSuccess() && confirmation != null;
    }

    /** Worked, and handed back a token nobody has to hold a key for. */
    public boolean unbound() {
        return isSuccess() && confirmation == null;
    }
}

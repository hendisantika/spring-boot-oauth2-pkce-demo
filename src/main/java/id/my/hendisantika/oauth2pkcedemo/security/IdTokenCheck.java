package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 11.05
 */
public record IdTokenCheck(String label,
                           String description,
                           String outcome,
                           String detail,
                           boolean refused,
                           boolean attack) implements Serializable {

    /** A substitution that was noticed. */
    public boolean isCaught() {
        return attack && refused;
    }

    /** A substitution that was not - which is the interesting half of this page. */
    public boolean isGap() {
        return attack && !refused;
    }
}

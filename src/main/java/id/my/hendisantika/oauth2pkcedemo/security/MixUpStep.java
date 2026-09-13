package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 18.33
 */
public record MixUpStep(String actor,
                        String what,
                        String detail,
                        boolean harmful) implements Serializable {

    public static MixUpStep of(String actor, String what, String detail) {
        return new MixUpStep(actor, what, detail, false);
    }

    /** A step where something the attacker wanted actually happened. */
    public static MixUpStep harmful(String actor, String what, String detail) {
        return new MixUpStep(actor, what, detail, true);
    }
}

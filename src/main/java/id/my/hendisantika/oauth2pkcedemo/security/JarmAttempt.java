package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 11.30
 */
public record JarmAttempt(String label,
                          String responseMode,
                          Map<String, String> parameters,
                          boolean signed,
                          Boolean signatureVerifies,
                          Map<String, Object> claims,
                          String jwt,
                          String note) implements Serializable {

    /** Whether the answer arrived as loose parameters anybody could have written. */
    public boolean isInTheClear() {
        return !signed;
    }
}

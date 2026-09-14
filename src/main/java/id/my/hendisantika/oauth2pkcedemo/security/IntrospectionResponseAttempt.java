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
 * Time: 08.15
 */
public record IntrospectionResponseAttempt(String label,
                                           String askedFor,
                                           String contentType,
                                           boolean signed,
                                           String type,
                                           String issuer,
                                           String audience,
                                           Boolean signatureVerifies,
                                           Map<String, Object> introspection,
                                           String token) implements Serializable {

    /** Whether the answer said the token was live, whatever form the answer took. */
    public boolean isActive() {
        return Boolean.TRUE.equals(introspection.get("active"));
    }
}

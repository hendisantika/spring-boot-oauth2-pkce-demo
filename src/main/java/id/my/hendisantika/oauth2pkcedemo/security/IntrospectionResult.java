package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.56
 */
public record IntrospectionResult(String tokenType,
                                  boolean active,
                                  Map<String, Object> claims,
                                  Instant checkedAt) implements Serializable {

    public static IntrospectionResult of(String tokenType, Map<String, Object> body) {
        boolean active = Boolean.TRUE.equals(body.get("active"));
        // RFC 7662 section 2.2: an inactive token yields exactly {"active": false} and nothing else,
        // so an unknown, expired or revoked token is indistinguishable from a made-up one.
        return new IntrospectionResult(tokenType, active, new TreeMap<>(body), Instant.now());
    }
}

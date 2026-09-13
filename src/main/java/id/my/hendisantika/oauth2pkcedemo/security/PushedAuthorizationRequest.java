package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Duration;
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
 * Time: 14.16
 */
public record PushedAuthorizationRequest(String registrationId,
                                         Map<String, String> pushedParameters,
                                         String requestUri,
                                         Instant expiresAt,
                                         String frontChannelUri,
                                         String traditionalUri,
                                         Instant pushedAt) implements Serializable {

    public PushedAuthorizationRequest {
        pushedParameters = new TreeMap<>(pushedParameters);
    }

    public long secondsRemaining() {
        return Math.max(0, Duration.between(Instant.now(), expiresAt).toSeconds());
    }

    /**
     * The whole point of RFC 9126: what the browser carries shrinks to a client id and an opaque
     * handle, however large the real request gets.
     */
    public int frontChannelLength() {
        return frontChannelUri.length();
    }

    public int traditionalLength() {
        return traditionalUri.length();
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.40
 */
public record DevicePollResult(Status status,
                               String error,
                               String errorDescription,
                               String accessToken,
                               String refreshToken,
                               Set<String> scopes,
                               Instant expiresAt) implements Serializable {

    /**
     * The states RFC 8628 section 3.5 defines for a device polling the token endpoint.
     */
    public enum Status {
        /** The user has not finished approving yet; keep polling. */
        PENDING,
        /** Polling too fast; the device must lengthen its interval. */
        SLOW_DOWN,
        /** Tokens issued. */
        GRANTED,
        /** The user said no. */
        DENIED,
        /** The device code timed out before anyone approved it. */
        EXPIRED,
        /** Anything else the token endpoint objected to. */
        ERROR
    }

    public static DevicePollResult pending(String error) {
        return new DevicePollResult(Status.PENDING, error, null, null, null, null, null);
    }

    public static DevicePollResult of(Status status, String error, String description) {
        return new DevicePollResult(status, error, description, null, null, null, null);
    }

    public static DevicePollResult granted(String accessToken, String refreshToken,
                                           Set<String> scopes, Instant expiresAt) {
        return new DevicePollResult(Status.GRANTED, null, null, accessToken, refreshToken, scopes, expiresAt);
    }

    public String accessTokenFingerprint() {
        if (accessToken == null) {
            return "-";
        }
        return accessToken.length() <= 28
                ? accessToken
                : accessToken.substring(0, 16) + "…" + accessToken.substring(accessToken.length() - 10);
    }
}

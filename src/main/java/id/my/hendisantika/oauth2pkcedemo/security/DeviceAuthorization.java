package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.40
 */
public record DeviceAuthorization(String deviceCode,
                                  String userCode,
                                  String verificationUri,
                                  String verificationUriComplete,
                                  Instant expiresAt,
                                  int intervalSeconds,
                                  Instant requestedAt) implements Serializable {

    public long secondsRemaining() {
        return Math.max(0, Duration.between(Instant.now(), expiresAt).toSeconds());
    }

    public boolean isExpired() {
        return secondsRemaining() == 0;
    }

    /**
     * The device code is the device's half of the exchange and never leaves it - only the short
     * user code is meant to be read aloud or typed into a browser.
     */
    public String deviceCodeFingerprint() {
        return deviceCode.length() <= 24
                ? deviceCode
                : deviceCode.substring(0, 12) + "…" + deviceCode.substring(deviceCode.length() - 8);
    }
}

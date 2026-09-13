package id.my.hendisantika.oauth2pkcedemo.security;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.io.Serializable;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.21
 */
public record TokenSnapshot(String tokenType,
                            Set<String> scopes,
                            Instant issuedAt,
                            Instant expiresAt,
                            String accessTokenValue,
                            String refreshTokenValue) implements Serializable {

    public static TokenSnapshot of(OAuth2AuthorizedClient authorizedClient) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
        return new TokenSnapshot(
                accessToken.getTokenType().getValue(),
                new LinkedHashSet<>(accessToken.getScopes()),
                accessToken.getIssuedAt(),
                accessToken.getExpiresAt(),
                accessToken.getTokenValue(),
                refreshToken == null ? null : refreshToken.getTokenValue());
    }

    /**
     * Enough of the token to recognise it on screen without printing the whole JWT twice.
     */
    public String accessTokenFingerprint() {
        return fingerprint(accessTokenValue);
    }

    public String refreshTokenFingerprint() {
        return fingerprint(refreshTokenValue);
    }

    private static String fingerprint(String value) {
        if (value == null) {
            return "-";
        }
        return value.length() <= 24 ? value : value.substring(0, 12) + "…" + value.substring(value.length() - 8);
    }
}

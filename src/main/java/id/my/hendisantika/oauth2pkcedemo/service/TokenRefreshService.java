package id.my.hendisantika.oauth2pkcedemo.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.21
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenRefreshService {

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> tokenResponseClient =
            new RestClientRefreshTokenTokenResponseClient();

    /**
     * Runs the refresh_token grant on demand and stores the result.
     * <p>
     * This deliberately bypasses {@code RefreshTokenOAuth2AuthorizedClientProvider}, which only
     * refreshes once the access token is close to expiry - the point of the demo page is to trigger
     * the exchange while the current token is still perfectly valid.
     *
     * @return the re-issued authorized client, now saved over the previous one
     * @throws IllegalStateException if the authorization carried no refresh token
     */
    public OAuth2AuthorizedClient refresh(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
        if (refreshToken == null) {
            throw new IllegalStateException("The current authorization has no refresh token to exchange");
        }

        OAuth2AccessTokenResponse response = tokenResponseClient.getTokenResponse(new OAuth2RefreshTokenGrantRequest(
                authorizedClient.getClientRegistration(), authorizedClient.getAccessToken(), refreshToken));

        OAuth2AccessToken newAccessToken = response.getAccessToken();
        // The authorization server is configured with reuseRefreshTokens(false), so a rotated
        // refresh token comes back. Fall back to the old one if a server ever omits it.
        OAuth2RefreshToken newRefreshToken =
                response.getRefreshToken() != null ? response.getRefreshToken() : refreshToken;

        OAuth2AuthorizedClient refreshed = new OAuth2AuthorizedClient(
                authorizedClient.getClientRegistration(), principal.getName(), newAccessToken, newRefreshToken);
        authorizedClientService.saveAuthorizedClient(refreshed, principal);

        log.debug("Refreshed access token for [{}], new expiry {}", principal.getName(), newAccessToken.getExpiresAt());
        return refreshed;
    }
}

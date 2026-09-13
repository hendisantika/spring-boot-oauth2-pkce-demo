package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.service.TokenAdminService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.42
 */
@Slf4j
public final class RevokingLogoutHandler implements LogoutHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenAdminService tokenAdminService;

    public RevokingLogoutHandler(OAuth2AuthorizedClientService authorizedClientService,
                                 TokenAdminService tokenAdminService) {
        this.authorizedClientService = authorizedClientService;
        this.tokenAdminService = tokenAdminService;
    }

    /**
     * Neither logout in OAuth touches a token. Spring Security's clears the session;
     * {@code OidcLogoutAuthenticationSuccessHandler} runs a {@code SecurityContextLogoutHandler} and
     * nothing else. Both leave an access token valid until it expires and a refresh token able to
     * mint new ones - so a client that wants signing out to mean anything has to say so itself, with
     * RFC 7009.
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
            revoke(oauth2Authentication);
        }
    }

    /**
     * Revokes the refresh token first: doing so invalidates the authorization it came from, taking
     * the access token with it. The access token is then revoked explicitly anyway, because a client
     * should not have to rely on that.
     *
     * @return what the revocation endpoint answered, empty when the session held no tokens
     */
    public List<RevocationResult> revoke(OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
        if (authorizedClient == null) {
            return List.of();
        }

        List<RevocationResult> results = new ArrayList<>();
        if (authorizedClient.getRefreshToken() != null) {
            results.add(this.tokenAdminService.revoke(
                    authorizedClient.getRefreshToken().getTokenValue(), TokenAdminService.REFRESH_TOKEN));
        }
        results.add(this.tokenAdminService.revoke(
                authorizedClient.getAccessToken().getTokenValue(), TokenAdminService.ACCESS_TOKEN));

        // The client's own copy goes too. Leaving it would mean holding credentials that no longer
        // work, which is how a refresh loop ends up failing long after anyone stopped watching.
        this.authorizedClientService.removeAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());

        log.debug("Revoked {} token(s) on logout for [{}]", results.size(), authentication.getName());
        return results;
    }
}

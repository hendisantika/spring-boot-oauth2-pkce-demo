package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.entity.CibaRequest;
import id.my.hendisantika.oauth2pkcedemo.service.CibaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
@Slf4j
@RequiredArgsConstructor
public final class CibaAuthenticationProvider implements AuthenticationProvider {

    private final CibaService cibaService;
    private final UserDetailsService userDetailsService;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    /**
     * Answers the client's poll. The three "not yet" cases are ordinary parts of the flow rather
     * than failures, and each has its own error code the client is expected to act on.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CibaAuthenticationToken cibaAuthentication = (CibaAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal =
                (OAuth2ClientAuthenticationToken) cibaAuthentication.getPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        CibaRequest request = cibaService.find(cibaAuthentication.getAuthReqId())
                .orElseThrow(() -> error(OAuth2ErrorCodes.INVALID_GRANT, "Unknown auth_req_id"));
        if (!request.getClientId().equals(registeredClient.getClientId())) {
            // A request belongs to the client that opened it; nobody else may collect its token.
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "auth_req_id belongs to another client");
        }
        if (request.isExpired() && request.getStatus() == CibaRequest.Status.PENDING) {
            throw error("expired_token", "The request expired before it was approved");
        }

        switch (request.getStatus()) {
            case PENDING -> throw error("authorization_pending", "The user has not answered yet");
            case DENIED -> throw error(OAuth2ErrorCodes.ACCESS_DENIED, "The user refused the request");
            case CONSUMED -> throw error(OAuth2ErrorCodes.INVALID_GRANT, "This approval was already used");
            case APPROVED -> {
                // fall through to issuing
            }
        }

        UserDetails user = userDetailsService.loadUserByUsername(request.getPrincipalName());
        Authentication principal = new CibaUserAuthentication(user);
        Set<String> scopes = request.scopeSet();

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(user.getUsername())
                .authorizationGrantType(CibaAuthenticationToken.CIBA_GRANT_TYPE)
                .authorizedScopes(scopes)
                .attribute(Principal.class.getName(), principal);

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(
                        org.springframework.security.oauth2.server.authorization.context
                                .AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(CibaAuthenticationToken.CIBA_GRANT_TYPE)
                .authorizationGrant(cibaAuthentication)
                .build();

        OAuth2Token generated = tokenGenerator.generate(tokenContext);
        if (generated == null) {
            throw error(OAuth2ErrorCodes.SERVER_ERROR, "Unable to generate the access token");
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generated.getTokenValue(), generated.getIssuedAt(), generated.getExpiresAt(), scopes);

        authorizationBuilder.accessToken(accessToken);
        authorizationService.save(authorizationBuilder.build());
        cibaService.markConsumed(request);
        log.debug("Issued a CIBA token for [{}]", user.getUsername());

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken,
                null, Map.of());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CibaAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2AuthenticationException error(String errorCode, String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(errorCode, description,
                "https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html"));
    }
}

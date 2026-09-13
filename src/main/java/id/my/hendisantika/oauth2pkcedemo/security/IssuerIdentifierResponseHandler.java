package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 18.33
 */
@Slf4j
public final class IssuerIdentifierResponseHandler
        implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    /** RFC 9207 section 2: the authorization response parameter naming the server that sent it. */
    public static final String ISS = "iss";

    /** RFC 9207 section 3: what a server advertises so a client knows to expect the parameter. */
    public static final String ISS_PARAMETER_SUPPORTED = "authorization_response_iss_parameter_supported";

    /** OpenID Connect Session Management section 2: required of a server that supports it. */
    public static final String SESSION_STATE = "session_state";

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String issuerUri;

    public IssuerIdentifierResponseHandler(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    /**
     * RFC 9207 section 2. Spring Authorization Server's own handler sends {@code code} and
     * {@code state} and stops there, which leaves a client that talks to more than one
     * authorization server unable to tell which one answered. Everything below matches what it does;
     * the addition is {@code iss}.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequest =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        OAuth2AuthorizationCode authorizationCode = authorizationCodeRequest.getAuthorizationCode();

        UriComponentsBuilder redirect =
                UriComponentsBuilder.fromUriString(authorizationCodeRequest.getRedirectUri())
                        .queryParam(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue());
        appendState(redirect, authorizationCodeRequest.getState());
        appendIssuer(redirect);
        appendSessionState(redirect, request, response, authorizationCodeRequest);

        log.debug("Sending an authorization response identified as {}", this.issuerUri);
        // build(true): the components above are already encoded, as they are in the handler this
        // replaces.
        this.redirectStrategy.sendRedirect(request, response, redirect.build(true).toUriString());
    }

    /**
     * An error response is an authorization response too, and RFC 9207 section 2.1 asks for
     * {@code iss} on it for the same reason: a client must be able to attribute what it receives.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestException =
                (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
        OAuth2Error error = authorizationCodeRequestException.getError();
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequest =
                authorizationCodeRequestException.getAuthorizationCodeRequestAuthentication();

        if (authorizationCodeRequest == null
                || !StringUtils.hasText(authorizationCodeRequest.getRedirectUri())) {
            // Nowhere safe to send this: without a validated redirect URI, reporting the error by
            // redirect would be an open redirect.
            response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
            return;
        }

        UriComponentsBuilder redirect =
                UriComponentsBuilder.fromUriString(authorizationCodeRequest.getRedirectUri())
                        .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
        appendEncoded(redirect, OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
        appendEncoded(redirect, OAuth2ParameterNames.ERROR_URI, error.getUri());
        appendState(redirect, authorizationCodeRequest.getState());
        appendIssuer(redirect);

        this.redirectStrategy.sendRedirect(request, response, redirect.build(true).toUriString());
    }

    /**
     * OpenID Connect Session Management section 2. The value is a hash the browser can recompute
     * from the same inputs, so an OP iframe can answer "is this still the session you were told
     * about?" without a request reaching the server at all.
     */
    private static void appendSessionState(UriComponentsBuilder redirect, HttpServletRequest request,
                                           HttpServletResponse response,
                                           OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequest) {
        String clientId = authorizationCodeRequest.getClientId();
        String origin = OpBrowserState.originOf(authorizationCodeRequest.getRedirectUri());
        String browserState = OpBrowserState.ensure(request, response);
        String sessionState = OpBrowserState.sessionState(clientId, origin, browserState,
                OpBrowserState.newSalt());
        redirect.queryParam(SESSION_STATE, UriUtils.encode(sessionState, StandardCharsets.UTF_8));
    }

    private void appendIssuer(UriComponentsBuilder redirect) {
        redirect.queryParam(ISS, UriUtils.encode(this.issuerUri, StandardCharsets.UTF_8));
    }

    private static void appendState(UriComponentsBuilder redirect, String state) {
        appendEncoded(redirect, OAuth2ParameterNames.STATE, state);
    }

    private static void appendEncoded(UriComponentsBuilder redirect, String name, String value) {
        if (StringUtils.hasText(value)) {
            redirect.queryParam(name, UriUtils.encode(value, StandardCharsets.UTF_8));
        }
    }
}

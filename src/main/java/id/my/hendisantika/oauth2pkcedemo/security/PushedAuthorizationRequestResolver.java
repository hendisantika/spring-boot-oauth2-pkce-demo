package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.service.PushedAuthorizationRequestService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.16
 */
@Slf4j
public class PushedAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    public static final String SESSION_ATTRIBUTE = PushedAuthorizationRequestResolver.class.getName();
    static final String REQUEST_URI = "request_uri";

    private final OAuth2AuthorizationRequestResolver delegate;
    private final PushedAuthorizationRequestService pushedAuthorizationRequestService;
    private final String parRegistrationId;

    public PushedAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                              PushedAuthorizationRequestService pushedAuthorizationRequestService,
                                              String parRegistrationId) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");
        this.pushedAuthorizationRequestService = pushedAuthorizationRequestService;
        this.parRegistrationId = parRegistrationId;
    }

    public static PushedAuthorizationRequest lastPushed(jakarta.servlet.http.HttpSession session) {
        return session == null ? null : (PushedAuthorizationRequest) session.getAttribute(SESSION_ATTRIBUTE);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return push(this.delegate.resolve(request), request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return push(this.delegate.resolve(request, clientRegistrationId), request);
    }

    /**
     * Sends the request the delegate built to the PAR endpoint and swaps only the browser-visible
     * URI for a short one. Everything else on the request is left alone - the state, the PKCE code
     * verifier, the redirect URI - so the callback is handled by the usual machinery and nothing
     * downstream needs to know PAR happened.
     */
    private OAuth2AuthorizationRequest push(OAuth2AuthorizationRequest authorizationRequest,
                                            HttpServletRequest request) {
        if (authorizationRequest == null) {
            return null;
        }
        String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        // Only the confidential client can push: the endpoint demands client authentication, and the
        // public client has nothing to authenticate with.
        if (!this.parRegistrationId.equals(registrationId)) {
            return authorizationRequest;
        }

        Map<String, String> parameters = pushedParameters(authorizationRequest);
        PushedAuthorizationRequestService.PushedRequestUri pushed =
                this.pushedAuthorizationRequestService.push(parameters);

        String frontChannelUri = UriComponentsBuilder
                .fromUriString(authorizationRequest.getAuthorizationUri())
                .queryParam(OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getClientId())
                .queryParam(REQUEST_URI, pushed.requestUri())
                .build()
                .toUriString();

        request.getSession().setAttribute(SESSION_ATTRIBUTE, new PushedAuthorizationRequest(
                registrationId,
                parameters,
                pushed.requestUri(),
                Instant.now().plus(pushed.expiresIn()),
                frontChannelUri,
                authorizationRequest.getAuthorizationRequestUri(),
                Instant.now()));

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .authorizationRequestUri(frontChannelUri)
                .build();
    }

    private static Map<String, String> pushedParameters(OAuth2AuthorizationRequest authorizationRequest) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE,
                authorizationRequest.getResponseType().getValue());
        parameters.put(OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getClientId());
        parameters.put(OAuth2ParameterNames.REDIRECT_URI, authorizationRequest.getRedirectUri());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", authorizationRequest.getScopes()));
        parameters.put(OAuth2ParameterNames.STATE, authorizationRequest.getState());
        authorizationRequest.getAdditionalParameters()
                .forEach((name, value) -> parameters.put(name, String.valueOf(value)));
        return parameters;
    }
}

package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
@Slf4j
public class PkceAuditingAuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String SESSION_ATTRIBUTE = PkceAuditingAuthorizationRequestRepository.class.getName();

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> delegate =
            new HttpSessionOAuth2AuthorizationRequestRepository();

    /**
     * Reads back the PKCE parameters recorded for the current session, so the UI can show the
     * verifier and challenge that were actually used. Returns {@code null} before the first login.
     */
    public static PkceExchange currentExchange(HttpSession session) {
        return session == null ? null : (PkceExchange) session.getAttribute(SESSION_ATTRIBUTE);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return delegate.loadAuthorizationRequest(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        delegate.saveAuthorizationRequest(authorizationRequest, request, response);
        if (authorizationRequest != null) {
            record(authorizationRequest, request);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        // Deliberately leaves the audited PkceExchange in the session: the authorization request
        // itself is single-use, but the demo pages still want to display what was sent.
        return delegate.removeAuthorizationRequest(request, response);
    }

    private void record(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
        String codeChallenge = (String) authorizationRequest.getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        if (codeChallenge == null) {
            log.warn("Authorization request for [{}] carries no code_challenge - PKCE is not in play",
                    (String) authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID));
            return;
        }
        PkceExchange exchange = new PkceExchange(
                authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID),
                authorizationRequest.getState(),
                authorizationRequest.getAttribute(PkceParameterNames.CODE_VERIFIER),
                codeChallenge,
                (String) authorizationRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD),
                authorizationRequest.getAuthorizationRequestUri(),
                Instant.now());
        request.getSession().setAttribute(SESSION_ATTRIBUTE, exchange);
        log.debug("PKCE authorization request: challenge={} method={}", codeChallenge, exchange.codeChallengeMethod());
    }
}

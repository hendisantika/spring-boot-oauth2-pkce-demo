package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.AuthorizationServerConfig;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientFrontChannelLogoutController {

    /** The client's side of it, one endpoint per registration, loaded in an iframe by the browser. */
    public static final String LOGOUT_URI = "/frontchannel/logout/";

    /** OpenID Connect Front-Channel Logout section 2: what the query string may carry, and all it may. */
    public static final String ISSUER = "iss";

    public static final String SESSION_ID = "sid";

    private final SecurityContextLogoutHandler securityContextLogoutHandler =
            new SecurityContextLogoutHandler();

    private final DemoProperties properties;

    /**
     * OpenID Connect Front-Channel Logout section 3. The request arrives in an iframe, carrying the
     * client's own cookies and nothing else - no token, no signature, nothing the client can verify.
     * All it can do is check that the {@code iss} and {@code sid} match the session it already has,
     * and end that session if they do.
     * <p>
     * Answers 200 whatever happens, because there is nobody to answer to: the authorization server
     * rendered an iframe and cannot see what came back.
     */
    @GetMapping(LOGOUT_URI + "{registrationId}")
    @ResponseBody
    public ResponseEntity<String> logout(@PathVariable String registrationId,
                                         @RequestParam(name = ISSUER, required = false) String issuer,
                                         @RequestParam(name = SESSION_ID, required = false) String sessionId,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String outcome = end(registrationId, issuer, sessionId, authentication, request, response);
        log.debug("Front-channel logout for [{}]: {}", registrationId, outcome);
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(outcome);
    }

    private String end(String registrationId, String issuer, String sessionId,
                       Authentication authentication, HttpServletRequest request,
                       HttpServletResponse response) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            // No cookie reached this iframe, or there was never a session here. A client cannot tell
            // those apart, and neither can the server that sent the iframe.
            return "no session to end";
        }
        if (!registrationId.equals(oauth2Authentication.getAuthorizedClientRegistrationId())) {
            return "not this client's session";
        }
        if (issuer != null && !properties.issuerUri().equals(issuer)) {
            return "iss does not match the provider this session came from";
        }
        if (sessionId != null && !sessionId.equals(sessionIdOf(oauth2Authentication))) {
            return "sid names a different session";
        }

        securityContextLogoutHandler.logout(request, response, authentication);
        return "session ended";
    }

    private static String sessionIdOf(OAuth2AuthenticationToken authentication) {
        return authentication.getPrincipal() instanceof OidcUser user
                ? user.getIdToken().getClaimAsString(AuthorizationServerConfig.SESSION_ID)
                : null;
    }
}

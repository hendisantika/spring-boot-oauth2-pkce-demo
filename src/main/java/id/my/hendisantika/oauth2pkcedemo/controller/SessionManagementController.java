package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.OpBrowserState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.25
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class SessionManagementController {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final DemoProperties properties;

    /**
     * Everything the RP iframe needs to start polling: the client id it was issued to, a session
     * state to send, and the origin it must refuse messages from anything else.
     * <p>
     * The session state is recomputed here rather than read off the authorization response, because
     * Spring's OAuth2 client has no field for {@code session_state} and drops it - the same gap as
     * {@code iss} before it. The inputs are identical, so the value behaves identically.
     */
    @GetMapping("/session-management")
    public String sessionManagementPage(Authentication authentication, HttpServletRequest request,
                                        HttpServletResponse response, Model model) {
        String clientId = clientId(authentication);

        String origin = OpBrowserState.originOf(properties.issuerUri());
        String browserState = OpBrowserState.ensure(request, response);
        String salt = OpBrowserState.newSalt();

        model.addAttribute("signedIn", clientId != null);
        model.addAttribute("clientId", clientId == null ? properties.client().clientId() : clientId);
        model.addAttribute("origin", origin);
        model.addAttribute("browserState", browserState);
        model.addAttribute("salt", salt);
        model.addAttribute("sessionState", OpBrowserState.sessionState(
                clientId == null ? properties.client().clientId() : clientId, origin, browserState, salt));
        model.addAttribute("checkSessionUri", properties.issuerUri() + CheckSessionIframeController.URI);
        model.addAttribute("cookieName", OpBrowserState.COOKIE_NAME);
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        return "session-management";
    }

    /**
     * Stands in for whatever else would have changed it - a sign-out in another tab, a different
     * user signing in, an administrator ending the session. The OP iframe has no idea which of those
     * happened, and neither will the client: all it learns is that the value it was given no longer
     * matches.
     */
    @PostMapping("/session-management/change")
    public String changeBrowserState(HttpServletResponse response) {
        log.debug("Changed the OP browser state to {}", OpBrowserState.refresh(response));
        return "redirect:/session-management";
    }

    /** The client id the session was issued to, which is what the session state was computed from. */
    private String clientId(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            return null;
        }
        ClientRegistration registration = clientRegistrationRepository
                .findByRegistrationId(oauth2Authentication.getAuthorizedClientRegistrationId());
        return registration == null ? null : registration.getClientId();
    }
}

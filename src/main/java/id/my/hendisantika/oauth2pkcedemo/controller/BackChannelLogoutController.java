package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.AuthorizationServerConfig;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.BackChannelLogoutService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
@Controller
@RequiredArgsConstructor
public class BackChannelLogoutController {

    private final BackChannelLogoutService backChannelLogoutService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final DemoProperties properties;

    /**
     * Reachable signed out: a run ends with the session gone, and the result is looked up by the id
     * in the query string rather than from the session that was just ended.
     */
    @GetMapping("/backchannel-logout")
    public String backChannelLogoutPage(@RequestParam(name = "run", required = false) String runId,
                                        Authentication authentication,
                                        Model model) {
        boolean signedIn = authentication instanceof OAuth2AuthenticationToken;
        ClientRegistration registration = registration(authentication);

        model.addAttribute("run", backChannelLogoutService.find(runId));
        model.addAttribute("canRun", signedIn);
        model.addAttribute("clientName", registration == null ? null : registration.getClientName());
        model.addAttribute("backChannelUri", backChannelLogoutService.backChannelUri(
                registration == null ? properties.client().registrationId() : registration.getRegistrationId()));
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        return "backchannel-logout";
    }

    /**
     * Sends the logout tokens from this application to itself over HTTP. Nothing about the run goes
     * through the browser, which is what makes the session ending afterwards worth seeing.
     */
    @PostMapping("/backchannel-logout")
    public String run(Authentication authentication, HttpSession session) {
        ClientRegistration registration = registration(authentication);
        if (registration == null) {
            return "redirect:/backchannel-logout";
        }
        String runId = backChannelLogoutService.run(registration, authentication.getName(),
                sessionId(authentication), session);
        return "redirect:/backchannel-logout?run=" + runId;
    }

    /**
     * The {@code sid} the ID token was issued with. The logout token has to name the same value, or
     * the client looks for a session that does not exist.
     */
    private static String sessionId(Authentication authentication) {
        return authentication.getPrincipal() instanceof OidcUser user
                ? user.getIdToken().getClaimAsString(AuthorizationServerConfig.SESSION_ID)
                : null;
    }

    private ClientRegistration registration(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            return null;
        }
        return clientRegistrationRepository.findByRegistrationId(
                oauth2Authentication.getAuthorizedClientRegistrationId());
    }
}

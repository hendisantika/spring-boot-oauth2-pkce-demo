package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.AuthorizationServerConfig;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelLogoutTarget;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelProbe;
import id.my.hendisantika.oauth2pkcedemo.service.FrontChannelLogoutService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
@Controller
@RequiredArgsConstructor
public class FrontChannelLogoutController {

    private final FrontChannelLogoutService frontChannelLogoutService;
    private final DemoProperties properties;

    /**
     * Reachable signed out, because the iframes on it end the session that loaded them. The run is
     * looked up by the id in the query string for the same reason.
     */
    @GetMapping("/frontchannel-logout")
    public String frontChannelLogoutPage(@RequestParam(name = "run", required = false) String runId,
                                         Authentication authentication,
                                         Model model) {
        String sessionId = sessionId(authentication);
        model.addAttribute("run", frontChannelLogoutService.find(runId));
        model.addAttribute("canRun", sessionId != null);
        model.addAttribute("preview", frontChannelLogoutService.targets(
                sessionId == null ? "the-session-that-ended" : sessionId));
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        return "frontchannel-logout";
    }

    /**
     * Builds what the authorization server would render, and probes the same URIs from here - the
     * browser loads the real iframes when the page comes back, which is the half only it can do.
     */
    @PostMapping("/frontchannel-logout")
    public String run(Authentication authentication) {
        String sessionId = sessionId(authentication);
        if (sessionId == null) {
            return "redirect:/frontchannel-logout";
        }
        List<FrontChannelLogoutTarget> targets = frontChannelLogoutService.targets(sessionId);
        List<FrontChannelProbe> probes = frontChannelLogoutService.probeWithoutCookies(targets);
        return "redirect:/frontchannel-logout?run="
                + frontChannelLogoutService.record(targets, probes, sessionId);
    }

    /** The {@code sid} the ID token carries, which is what a front-channel URI names. */
    private static String sessionId(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)
                || !(oauth2Authentication.getPrincipal() instanceof OidcUser user)) {
            return null;
        }
        return user.getIdToken().getClaimAsString(AuthorizationServerConfig.SESSION_ID);
    }
}

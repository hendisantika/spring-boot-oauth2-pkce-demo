package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutRevocationRun;
import id.my.hendisantika.oauth2pkcedemo.service.LogoutRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
 * Time: 19.42
 */
@Controller
@RequiredArgsConstructor
public class LogoutRevocationController {

    private final LogoutRevocationService logoutRevocationService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final DemoProperties properties;

    /**
     * Reachable signed out, because a run ends signed out: the result is fetched by the id in the
     * query string rather than from a session that no longer exists.
     */
    @GetMapping("/logout-revocation")
    public String logoutRevocationPage(@RequestParam(name = "run", required = false) String runId,
                                       Authentication authentication,
                                       Model model) {
        LogoutRevocationRun run = logoutRevocationService.find(runId);
        OAuth2AuthorizedClient authorizedClient = authorizedClient(authentication);

        model.addAttribute("run", run);
        model.addAttribute("canRun", authorizedClient != null
                && authorizedClient.getRefreshToken() != null);
        model.addAttribute("signedIn", authorizedClient != null);
        model.addAttribute("clientName", authorizedClient == null
                ? null : authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("confidentialLoginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());
        model.addAttribute("revokingClientId", properties.confidentialClient().clientId());
        return "logout-revocation";
    }

    /**
     * Signs the user out, one way or the other, and keeps what happened to the tokens. The response
     * cannot carry it in the session, since ending the session is the thing being measured.
     */
    @PostMapping("/logout-revocation")
    public String run(@RequestParam(defaultValue = "false") boolean revoke,
                      Authentication authentication,
                      HttpServletRequest request,
                      HttpServletResponse response) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)
                || authorizedClient(oauth2Authentication) == null) {
            return "redirect:/logout-revocation";
        }
        String runId = logoutRevocationService.run(oauth2Authentication, revoke, request, response);
        return "redirect:/logout-revocation?run=" + runId;
    }

    /**
     * Any session may land here, including one that only signed in at the form: the page is
     * reachable signed out, and asking Spring to resolve an {@link OAuth2AuthenticationToken}
     * argument against a session holding something else is a 500 rather than a null.
     */
    private OAuth2AuthorizedClient authorizedClient(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            return null;
        }
        return authorizedClientService.loadAuthorizedClient(
                oauth2Authentication.getAuthorizedClientRegistrationId(), oauth2Authentication.getName());
    }
}

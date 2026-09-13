package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationContextLevel;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.service.StepUpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
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
 * Time: 16.52
 */
@Controller
@RequiredArgsConstructor
public class StepUpController {

    private final StepUpService stepUpService;
    private final DemoProperties properties;
    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

    @GetMapping("/stepup")
    public String stepUpPage(Authentication authentication, Model model) {
        // Deliberately not showing the browser session's own acr: once a client login completes,
        // the session holds an OAuth2AuthenticationToken whose authorities are scopes and roles, not
        // the factors recorded at the authorization server. The ID token is the authority on this.
        model.addAttribute("loa1", AuthenticationContextLevel.LOA_1);
        model.addAttribute("loa2", AuthenticationContextLevel.LOA_2);

        if (authentication instanceof OAuth2AuthenticationToken
                && authentication.getPrincipal() instanceof OidcUser user) {
            // Straight off the ID token, so it is the authorization server's word for it.
            model.addAttribute("tokenAcr", user.getClaimAsString("acr"));
            model.addAttribute("tokenAmr", user.getClaim("amr"));
        }
        // The public client deliberately, not the PAR one: with a pushed request the browser
        // carries only a request_uri, so acr_values would never reach the authorization endpoint
        // where it is enforced.
        model.addAttribute("stepUpLoginUri", "/oauth2/authorization/"
                + properties.client().registrationId());
        return "stepup";
    }

    /**
     * The prompt the authorization endpoint sends users to when a request asks for a level the
     * session does not have.
     */
    @GetMapping(StepUpRequiredFilter.STEP_UP_URI)
    public String verifyPage(Authentication authentication, HttpSession session, Model model) {
        model.addAttribute("code", stepUpService.issueCode(session));
        model.addAttribute("username", authentication.getName());
        model.addAttribute("currentAcr", AuthenticationContextLevel.acrOf(authentication));
        return "stepup-verify";
    }

    @PostMapping(StepUpRequiredFilter.STEP_UP_URI)
    public String verify(@RequestParam("code") String code,
                         HttpSession session,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         Model model) {
        if (!stepUpService.verify(session, code)) {
            model.addAttribute("error", "That code did not match.");
            model.addAttribute("code", stepUpService.issueCode(session));
            model.addAttribute("username", request.getUserPrincipal().getName());
            model.addAttribute("currentAcr", AuthenticationContextLevel.LOA_1);
            return "stepup-verify";
        }

        // Resume whatever the authorization endpoint was in the middle of.
        SavedRequest saved = this.requestCache.getRequest(request, response);
        if (saved != null) {
            this.requestCache.removeRequest(request, response);
            return "redirect:" + saved.getRedirectUrl();
        }
        return "redirect:/stepup";
    }
}

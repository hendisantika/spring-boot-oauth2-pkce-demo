package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.IdTokenBindingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 11.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class IdTokenBindingController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final IdTokenBindingService idTokenBindingService;
    private final DemoProperties properties;

    /**
     * The page needs this session's own ID token, so a form login is not enough - it produces no
     * ID token at all. Taking {@link Authentication} rather than the OIDC type keeps such a session
     * on a card that says so instead of a 500.
     */
    @GetMapping("/idtoken-binding")
    public String idTokenBindingPage(Authentication authentication, Model model) {
        model.addAttribute("canRun", idToken(authentication) != null);
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        model.addAttribute("otherClientName", properties.confidentialClient().clientName());
        model.addAttribute("otherTokenClientId", idTokenBindingService.otherClientId());
        return "idtoken-binding";
    }

    @PostMapping("/idtoken-binding")
    public String run(Authentication authentication, RedirectAttributes redirectAttributes) {
        OidcUser user = idToken(authentication);
        if (user == null) {
            return "redirect:/idtoken-binding";
        }
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                token.getAuthorizedClientRegistrationId(), token.getName());
        try {
            redirectAttributes.addFlashAttribute("run", idTokenBindingService.run(
                    user.getIdToken(), authorizedClient.getAccessToken(),
                    token.getAuthorizedClientRegistrationId()));
        } catch (RuntimeException ex) {
            log.debug("ID token binding run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("idTokenError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/idtoken-binding";
    }

    private static OidcUser idToken(Authentication authentication) {
        return authentication instanceof OAuth2AuthenticationToken token
                && token.getPrincipal() instanceof OidcUser user ? user : null;
    }
}

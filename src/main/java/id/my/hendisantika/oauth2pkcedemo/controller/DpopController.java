package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.DpopService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
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
 * Date: 13/09/26
 * Time: 14.24
 */
@Controller
@RequiredArgsConstructor
public class DpopController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final DpopService dpopService;
    private final DemoProperties properties;

    @GetMapping("/dpop")
    public String dpopPage(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        boolean canRun = authorizedClient.getRefreshToken() != null;

        model.addAttribute("canRun", canRun);
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("confidentialLoginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());
        return "dpop";
    }

    /**
     * Uses the session's refresh token to obtain a DPoP-bound access token, because that grant needs
     * nothing from the browser - Spring's OAuth2 client has no DPoP support, so the authorization
     * code leg could not carry a proof without rebuilding it by hand.
     */
    @PostMapping("/dpop")
    public String run(OAuth2AuthenticationToken authentication, RedirectAttributes redirectAttributes) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        if (authorizedClient.getRefreshToken() == null) {
            redirectAttributes.addFlashAttribute("dpopError",
                    "This session has no refresh token to exchange.");
            return "redirect:/dpop";
        }
        try {
            redirectAttributes.addFlashAttribute("result",
                    dpopService.run(authorizedClient.getRefreshToken().getTokenValue()));
        } catch (OAuth2AuthorizationException | IllegalStateException ex) {
            redirectAttributes.addFlashAttribute("dpopError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/dpop";
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }
}

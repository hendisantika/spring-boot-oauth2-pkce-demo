package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.TokenSnapshot;
import id.my.hendisantika.oauth2pkcedemo.service.TokenAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.56
 */
@Controller
@RequiredArgsConstructor
public class TokenAdminController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenAdminService tokenAdminService;
    private final DemoProperties properties;

    @GetMapping("/introspect")
    public String introspectPage(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        TokenSnapshot current = TokenSnapshot.of(authorizedClient);

        model.addAttribute("current", current);
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("introspectingClientId", tokenAdminService.introspectingClientId());
        // Revocation is restricted to the client the token was issued to, so the page only offers it
        // when this session belongs to the client that holds the secret.
        model.addAttribute("ownsTokens", properties.confidentialClient().registrationId()
                .equals(authentication.getAuthorizedClientRegistrationId()));
        model.addAttribute("confidentialLoginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());
        return "introspect";
    }

    @PostMapping("/introspect")
    public String introspect(OAuth2AuthenticationToken authentication,
                             @RequestParam("token_type") String tokenType,
                             RedirectAttributes redirectAttributes) {
        String token = tokenValue(authentication, tokenType);
        if (token == null) {
            redirectAttributes.addFlashAttribute("tokenError", "This session holds no " + tokenType + ".");
            return "redirect:/introspect";
        }
        redirectAttributes.addFlashAttribute("introspection", tokenAdminService.introspect(token, tokenType));
        return "redirect:/introspect";
    }

    @PostMapping("/introspect/revoke")
    public String revoke(OAuth2AuthenticationToken authentication,
                         @RequestParam("token_type") String tokenType,
                         RedirectAttributes redirectAttributes) {
        String token = tokenValue(authentication, tokenType);
        if (token == null) {
            redirectAttributes.addFlashAttribute("tokenError", "This session holds no " + tokenType + ".");
            return "redirect:/introspect";
        }
        redirectAttributes.addFlashAttribute("revocation", tokenAdminService.revoke(token, tokenType));
        // Show what the token looks like afterwards: the same call that just said active now does not.
        redirectAttributes.addFlashAttribute("introspection", tokenAdminService.introspect(token, tokenType));
        return "redirect:/introspect";
    }

    private String tokenValue(OAuth2AuthenticationToken authentication, String tokenType) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        if (TokenAdminService.REFRESH_TOKEN.equals(tokenType)) {
            return authorizedClient.getRefreshToken() == null
                    ? null : authorizedClient.getRefreshToken().getTokenValue();
        }
        return authorizedClient.getAccessToken().getTokenValue();
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }
}

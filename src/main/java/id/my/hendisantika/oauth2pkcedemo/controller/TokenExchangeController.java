package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.TokenSnapshot;
import id.my.hendisantika.oauth2pkcedemo.service.TokenExchangeService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
 * Time: 15.04
 */
@Controller
@RequiredArgsConstructor
public class TokenExchangeController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenExchangeService tokenExchangeService;
    private final DemoProperties properties;

    @GetMapping("/exchange")
    public String exchangePage(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        TokenSnapshot subject = TokenSnapshot.of(authorizedClient);

        model.addAttribute("subject", subject);
        model.addAttribute("frontEndClientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("exchangeClientId", properties.exchangeClient().clientId());
        model.addAttribute("exchangeClientName", properties.exchangeClient().clientName());
        model.addAttribute("exchangeScopes", String.join(" ", properties.exchangeClient().scopes()));
        return "exchange";
    }

    /**
     * Hands the session's access token to the exchange client as if it had arrived on an API call,
     * which is the position a downstream service is actually in.
     */
    @PostMapping("/exchange")
    public String run(OAuth2AuthenticationToken authentication, RedirectAttributes redirectAttributes) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        redirectAttributes.addFlashAttribute("attempts",
                tokenExchangeService.run(authorizedClient.getAccessToken().getTokenValue()));
        return "redirect:/exchange";
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }
}

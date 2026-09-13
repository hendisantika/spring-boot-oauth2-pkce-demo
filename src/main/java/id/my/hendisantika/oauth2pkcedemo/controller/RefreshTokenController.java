package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.TokenSnapshot;
import id.my.hendisantika.oauth2pkcedemo.service.TokenRefreshService;
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

import java.time.Duration;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.21
 */
@Controller
@RequiredArgsConstructor
public class RefreshTokenController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenRefreshService tokenRefreshService;
    private final DemoProperties properties;

    @GetMapping("/refresh")
    public String refreshPage(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        TokenSnapshot current = TokenSnapshot.of(authorizedClient);
        model.addAttribute("current", current);
        model.addAttribute("secondsRemaining", secondsUntil(current.expiresAt()));
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("clientAuthenticationMethod",
                authorizedClient.getClientRegistration().getClientAuthenticationMethod().getValue());
        model.addAttribute("publicClient", current.refreshTokenValue() == null);
        model.addAttribute("confidentialLoginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());
        return "refresh";
    }

    /**
     * Exchanges the refresh token for a fresh access token and hands the before/after pair to the
     * page through flash attributes, so a reload does not replay the exchange.
     */
    @PostMapping("/refresh")
    public String refresh(OAuth2AuthenticationToken authentication, RedirectAttributes redirectAttributes) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        TokenSnapshot before = TokenSnapshot.of(authorizedClient);
        try {
            TokenSnapshot after = TokenSnapshot.of(tokenRefreshService.refresh(authorizedClient, authentication));
            redirectAttributes.addFlashAttribute("before", before);
            redirectAttributes.addFlashAttribute("after", after);
            redirectAttributes.addFlashAttribute("rotated",
                    after.refreshTokenValue() != null && !after.refreshTokenValue().equals(before.refreshTokenValue()));
        } catch (OAuth2AuthorizationException | IllegalStateException ex) {
            redirectAttributes.addFlashAttribute("refreshError", ex.getMessage());
        }
        return "redirect:/refresh";
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }

    private static long secondsUntil(Instant expiresAt) {
        return expiresAt == null ? 0 : Math.max(0, Duration.between(Instant.now(), expiresAt).toSeconds());
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.PkceAuditingAuthorizationRequestRepository;
import id.my.hendisantika.oauth2pkcedemo.security.PkceExchange;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
@Controller
@RequiredArgsConstructor
public class HomeController {

    private final DemoProperties properties;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("authorizationRequestUri",
                "/oauth2/authorization/" + properties.client().registrationId());
        model.addAttribute("issuerUri", properties.issuerUri());
        model.addAttribute("demoUsers", properties.demoUsers());
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OidcUser user,
                            OAuth2AuthenticationToken authentication,
                            HttpSession session,
                            Model model) {
        OAuth2AuthorizedClient authorizedClient = authorizedClient(authentication);
        model.addAttribute("user", user);
        model.addAttribute("idTokenClaims", sorted(user.getIdToken().getClaims()));
        model.addAttribute("accessToken", authorizedClient.getAccessToken());
        model.addAttribute("refreshToken", authorizedClient.getRefreshToken());
        model.addAttribute("pkce", PkceAuditingAuthorizationRequestRepository.currentExchange(session));
        return "dashboard";
    }

    @GetMapping("/tokens")
    public String tokens(@AuthenticationPrincipal OidcUser user,
                         OAuth2AuthenticationToken authentication,
                         HttpSession session,
                         Model model) {
        OAuth2AuthorizedClient authorizedClient = authorizedClient(authentication);
        PkceExchange pkce = PkceAuditingAuthorizationRequestRepository.currentExchange(session);
        model.addAttribute("pkce", pkce);
        model.addAttribute("idTokenValue", user.getIdToken().getTokenValue());
        model.addAttribute("idTokenClaims", sorted(user.getIdToken().getClaims()));
        model.addAttribute("accessToken", authorizedClient.getAccessToken());
        model.addAttribute("refreshToken", authorizedClient.getRefreshToken());
        model.addAttribute("userInfoClaims", sorted(user.getUserInfo() == null
                ? Map.of() : user.getUserInfo().getClaims()));
        return "tokens";
    }

    /**
     * Reads the tokens back out of the MySQL-backed authorized client store, keyed by the
     * registration the user actually logged in through.
     */
    private OAuth2AuthorizedClient authorizedClient(OAuth2AuthenticationToken authentication) {
        return authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }

    private static Map<String, Object> sorted(Map<String, Object> claims) {
        return new TreeMap<>(claims);
    }
}

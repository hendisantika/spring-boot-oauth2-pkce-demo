package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.RevokingLogoutHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.util.UriComponentsBuilder;

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
public class LogoutDemoController {

    public static final String END_SESSION_ENDPOINT = "end_session_endpoint";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RevokingLogoutHandler revokingLogoutHandler;
    private final DemoProperties properties;

    @GetMapping("/logout-demo")
    public String logoutPage(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("endSessionEndpoint", endSessionEndpoint());
        model.addAttribute("postLogoutRedirectUri", postLogoutRedirectUri());
        // Abbreviated on purpose: the full JWT is on /tokens, and printing it here buries the page.
        model.addAttribute("idTokenHint", abbreviate(user.getIdToken().getTokenValue()));
        return "logout-demo";
    }

    /**
     * RP-initiated logout (OpenID Connect Session Management). The browser is handed to the
     * authorization server's end session endpoint with the ID token as proof of who is signing out;
     * the server ends the session and redirects to a pre-registered post_logout_redirect_uri.
     * <p>
     * The local session is deliberately left intact here - invalidating it first would throw away
     * the ID token hint. Because this demo runs the client and the authorization server in one
     * application they share a session, so the server's invalidation ends both at once. Split across
     * two deployments these would be two separate sessions, and the client would also run its own
     * logout.
     * <p>
     * The tokens are revoked first, because ending a session is all the end session endpoint does -
     * see <a href="/logout-revocation">what that leaves behind</a>.
     */
    @PostMapping("/logout/rp-initiated")
    public String rpInitiatedLogout(@AuthenticationPrincipal OidcUser user,
                                    OAuth2AuthenticationToken authentication) {
        revokingLogoutHandler.revoke(authentication);
        String redirect = UriComponentsBuilder.fromUriString(endSessionEndpoint())
                .queryParam("id_token_hint", user.getIdToken().getTokenValue())
                .queryParam("post_logout_redirect_uri", postLogoutRedirectUri())
                .build()
                .toUriString();
        return "redirect:" + redirect;
    }

    private static String abbreviate(String token) {
        return token.length() <= 48 ? token : token.substring(0, 28) + "…" + token.substring(token.length() - 16);
    }

    private String endSessionEndpoint() {
        ClientRegistration registration =
                clientRegistrationRepository.findByRegistrationId(properties.client().registrationId());
        Object endSessionEndpoint =
                registration.getProviderDetails().getConfigurationMetadata().get(END_SESSION_ENDPOINT);
        return String.valueOf(endSessionEndpoint);
    }

    private String postLogoutRedirectUri() {
        // Must match a post_logout_redirect_uri registered against the client, or the authorization
        // server refuses to redirect back.
        return properties.issuerUri() + "/";
    }
}

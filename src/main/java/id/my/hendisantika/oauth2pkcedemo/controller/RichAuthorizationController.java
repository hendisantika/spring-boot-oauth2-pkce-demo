package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequestResolver;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationDetail;
import id.my.hendisantika.oauth2pkcedemo.service.PushedAuthorizationRequestService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.52
 */
@Controller
@RequiredArgsConstructor
public class RichAuthorizationController {

    static final String SAMPLE_PAYMENT = """
            [{
              "type": "payment_initiation",
              "actions": ["initiate"],
              "locations": ["https://api.example.com/payments"],
              "instructedAmount": {"currency": "EUR", "amount": "123.50"},
              "creditorName": "Merchant A"
            }]""";

    static final String SAMPLE_UNSUPPORTED = """
            [{
              "type": "open_the_vault",
              "actions": ["everything"]
            }]""";

    private final DemoProperties properties;
    private final PushedAuthorizationRequestService pushedAuthorizationRequestService;

    /**
     * Reachable signed out: the details travel with the authorization request, so the interesting
     * moment is before there is a session.
     */
    @GetMapping("/rar")
    public String rarPage(Authentication authentication, HttpSession session, Model model) {
        model.addAttribute("samplePayment", SAMPLE_PAYMENT);
        model.addAttribute("sampleUnsupported", SAMPLE_UNSUPPORTED);
        model.addAttribute("supportedTypes", RichAuthorizationDetail.SUPPORTED_TYPES);
        model.addAttribute("loginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());

        if (authentication instanceof OAuth2AuthenticationToken
                && authentication.getPrincipal() instanceof OidcUser user) {
            // Shown straight off the ID token, so it is the server's word rather than the page's.
            model.addAttribute("grantedDetails", user.getClaim("authorization_details"));
            model.addAttribute("signedInAs", user.getSubject());
        }
        return "rar";
    }

    /**
     * Stages the details for the next authorization request; the PAR resolver picks them up and
     * pushes them alongside everything else.
     */
    @PostMapping("/rar")
    public String start(@RequestParam("authorization_details") String authorizationDetails,
                        HttpSession session,
                        RedirectAttributes redirectAttributes) {
        // Ask the authorization server first, so a refusal is reported in its own words rather than
        // surfacing as a failed redirect halfway through a login.
        Optional<String> refusal = pushedAuthorizationRequestService.probe(authorizationDetails);
        if (refusal.isPresent()) {
            redirectAttributes.addFlashAttribute("refusal", refusal.get());
            return "redirect:/rar";
        }

        session.setAttribute(PushedAuthorizationRequestResolver.AUTHORIZATION_DETAILS_ATTRIBUTE,
                authorizationDetails);
        return "redirect:/oauth2/authorization/" + properties.confidentialClient().registrationId();
    }
}

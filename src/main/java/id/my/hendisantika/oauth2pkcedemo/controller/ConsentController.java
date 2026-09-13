package id.my.hendisantika.oauth2pkcedemo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

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
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    /**
     * Renders the scope approval screen the authorization endpoint redirects to. Submitting the
     * form posts straight back to /oauth2/authorize, which is what resumes the interrupted flow.
     */
    @GetMapping("/oauth2/consent")
    public String consent(Authentication principal,
                          Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new ResponseStatusException(BAD_REQUEST, "Unknown client_id " + clientId);
        }

        OAuth2AuthorizationConsent currentConsent =
                authorizationConsentService.findById(registeredClient.getId(), principal.getName());
        Set<String> alreadyApproved = currentConsent == null ? Set.of() : currentConsent.getScopes();

        Set<String> scopesToApprove = new LinkedHashSet<>();
        Set<String> previouslyApproved = new LinkedHashSet<>();
        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            // The openid scope is implied by an OIDC request and is never up for approval.
            if (OidcScopes.OPENID.equals(requestedScope)) {
                continue;
            }
            if (alreadyApproved.contains(requestedScope)) {
                previouslyApproved.add(requestedScope);
            } else {
                scopesToApprove.add(requestedScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("userCode", userCode);
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApproved));
        return "consent";
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> described = new LinkedHashSet<>();
        for (String scope : scopes) {
            described.add(new ScopeWithDescription(scope));
        }
        return described;
    }

    public record ScopeWithDescription(String scope, String description) {

        private static final String DEFAULT_DESCRIPTION =
                "Grant access to data you have not explicitly described here.";

        ScopeWithDescription(String scope) {
            this(scope, switch (scope) {
                case OidcScopes.PROFILE -> "Read your name and username.";
                case OidcScopes.EMAIL -> "Read your email address.";
                default -> DEFAULT_DESCRIPTION;
            });
        }
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.config.StrongResourceSecurityConfig;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpChallenge;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpChallengeRun;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.service.StepUpChallengeService;
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
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class StepUpChallengeController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final StepUpChallengeService stepUpChallengeService;
    private final DemoProperties properties;

    @GetMapping("/stepup-challenge")
    public String stepUpChallengePage(Authentication authentication, Model model) {
        StepUpChallengeRun run = stepUpChallengeService.runFor(authentication.getName());
        String acr = tokenAcr(authentication);

        model.addAttribute("run", run);
        model.addAttribute("tokenAcr", acr);
        model.addAttribute("tokenAmr", tokenClaim(authentication, "amr"));
        model.addAttribute("canCall", acr != null);
        model.addAttribute("transferUri", stepUpChallengeService.transferUri());
        model.addAttribute("requiredAcr", StrongResourceSecurityConfig.REQUIRED_ACR);
        model.addAttribute("maxAge", StrongResourceSecurityConfig.MAX_AGE_SECONDS);
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        // Whether the token now meets what the last challenge asked for, so the page can say which
        // step comes next rather than leaving the reader to compare two strings.
        StepUpChallenge pending = run.pendingChallenge();
        model.addAttribute("readyToRetry", pending != null && pending.acrValues() != null
                && pending.acrValues().equals(acr));
        return "stepup-challenge";
    }

    /** One call to the protected operation with whatever this session is currently holding. */
    @PostMapping("/stepup-challenge/call")
    public String call(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            return "redirect:/stepup-challenge";
        }
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                token.getAuthorizedClientRegistrationId(), token.getName());
        StepUpChallengeRun current = stepUpChallengeService.runFor(token.getName());
        String acr = tokenAcr(authentication);
        // Named for what the call actually carried rather than for its position in the list: a
        // second call made before the step-up finished is not "after the step-up".
        String label;
        if (StrongResourceSecurityConfig.REQUIRED_ACR.equals(acr)) {
            label = "Again, with the token the step-up produced";
        } else if (current.attempts().isEmpty() || current.succeeded()) {
            label = "With the token the client already had";
        } else {
            label = "Again, with a token that still falls short";
        }

        stepUpChallengeService.record(token.getName(), label,
                authorizedClient.getAccessToken().getTokenValue(), acr);
        return "redirect:/stepup-challenge";
    }

    /**
     * What a client does with the challenge: start a new authorization request asking for the level
     * the resource server named. Nothing here invents that value - it is read back off the header.
     */
    @GetMapping("/stepup-challenge/reauthorize")
    public String reauthorize(Authentication authentication) {
        StepUpChallenge challenge =
                stepUpChallengeService.runFor(authentication.getName()).pendingChallenge();
        if (challenge == null || challenge.acrValues() == null) {
            return "redirect:/stepup-challenge";
        }
        String uri = UriComponentsBuilder
                .fromPath("/oauth2/authorization/" + properties.client().registrationId())
                .queryParam(StepUpRequiredFilter.ACR_VALUES, challenge.acrValues())
                .build().encode(StandardCharsets.UTF_8).toUriString();
        log.debug("Re-authorizing for {} because the resource server asked", challenge.acrValues());
        return "redirect:" + uri;
    }

    @GetMapping("/stepup-challenge/reset")
    public String reset(Authentication authentication) {
        stepUpChallengeService.reset(authentication.getName());
        return "redirect:/stepup-challenge";
    }

    /** The authorization server's word for how the user authenticated, off the ID token. */
    private static String tokenAcr(Authentication authentication) {
        Object acr = tokenClaim(authentication, "acr");
        return acr == null ? null : String.valueOf(acr);
    }

    private static Object tokenClaim(Authentication authentication, String name) {
        return authentication instanceof OAuth2AuthenticationToken
                && authentication.getPrincipal() instanceof OidcUser user
                ? user.getClaim(name) : null;
    }
}

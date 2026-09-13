package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationFreshness;
import id.my.hendisantika.oauth2pkcedemo.service.FreshnessService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 15.10
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class FreshnessController {

    /** Registered for the probe's client and never served: the probe reads the code off the redirect. */
    public static final String CALLBACK_URI = "/freshness/callback";

    private static final String RUN_ATTRIBUTE = "freshness.run";

    /** Values chosen to bracket any session a reader is likely to be sitting on. */
    private static final List<Long> OFFERED_MAX_AGES = List.of(3600L, 300L, 60L, 0L);

    private final FreshnessService freshnessService;
    private final DemoProperties properties;

    @GetMapping("/freshness")
    public String freshnessPage(Authentication authentication, HttpSession session, Model model) {
        OidcIdToken idToken = idToken(authentication);
        Instant authTime = idToken == null ? null : idToken.getAuthenticatedAt();

        model.addAttribute("hasIdToken", idToken != null);
        model.addAttribute("loginUri", "/oauth2/authorization/" + properties.client().registrationId());
        model.addAttribute("authTime", authTime);
        model.addAttribute("age", authTime == null ? null
                : Duration.between(authTime, Instant.now()).toSeconds());
        model.addAttribute("amr", idToken == null ? null : idToken.getClaim("amr"));
        model.addAttribute("acr", idToken == null ? null : idToken.getClaimAsString("acr"));
        model.addAttribute("decisions", decisions(authTime));
        model.addAttribute("probeClientId", freshnessService.clientId());
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        return "freshness";
    }

    @PostMapping("/freshness")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, freshnessService.run());
        } catch (RuntimeException ex) {
            log.debug("Freshness run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("freshnessError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/freshness";
    }

    @GetMapping("/freshness/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/freshness";
    }

    /**
     * What the filter would make of each value, against the reader's own session rather than the
     * probe's. Computed here so the table needs no round trip to be true.
     */
    private static Map<Long, Boolean> decisions(Instant authTime) {
        Map<Long, Boolean> decisions = new LinkedHashMap<>();
        if (authTime == null) {
            return decisions;
        }
        for (Long maxAge : OFFERED_MAX_AGES) {
            // The filter's own rule, so the table cannot drift away from what would happen.
            decisions.put(maxAge, AuthenticationFreshness.satisfies(authTime, maxAge));
        }
        return decisions;
    }

    private static OidcIdToken idToken(Authentication authentication) {
        return authentication instanceof OAuth2AuthenticationToken
                && authentication.getPrincipal() instanceof OidcUser user ? user.getIdToken() : null;
    }
}

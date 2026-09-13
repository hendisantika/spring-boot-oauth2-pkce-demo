package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.SilentAuthService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
 * Date: 14/09/26
 * Time: 17.20
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class SilentAuthController {

    /** Registered for the probe's client; the probe reads the answer off the redirect itself. */
    public static final String CALLBACK_URI = "/silent-auth/callback";

    private static final String RUN_ATTRIBUTE = "silentAuth.run";

    private final SilentAuthService silentAuthService;
    private final DemoProperties properties;

    @GetMapping("/silent-auth")
    public String silentAuthPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", silentAuthService.clientId());
        model.addAttribute("authorizationEndpoint", properties.issuerUri() + "/oauth2/authorize");
        return "silent-auth";
    }

    @PostMapping("/silent-auth")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, silentAuthService.run());
        } catch (RuntimeException ex) {
            log.debug("Silent authentication run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("silentError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/silent-auth";
    }

    @GetMapping("/silent-auth/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/silent-auth";
    }
}

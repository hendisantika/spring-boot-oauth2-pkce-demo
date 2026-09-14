package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RarEnforcementService;
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
 * Time: 21.10
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RarEnforcementController {

    /** Registered for the probe's client; the probe reads the code off the redirect itself. */
    public static final String CALLBACK_URI = "/rar-enforcement/callback";

    private static final String RUN_ATTRIBUTE = "rarEnforcement.run";

    private final RarEnforcementService rarEnforcementService;

    @GetMapping("/rar-enforcement")
    public String rarEnforcementPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", rarEnforcementService.clientId());
        model.addAttribute("authorizationDetails", rarEnforcementService.authorizationDetails());
        model.addAttribute("paymentsUri", PaymentApiController.PAYMENTS_URI);
        return "rar-enforcement";
    }

    @PostMapping("/rar-enforcement")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, rarEnforcementService.run());
        } catch (RuntimeException ex) {
            log.debug("RAR enforcement run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("rarError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/rar-enforcement";
    }

    @GetMapping("/rar-enforcement/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/rar-enforcement";
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceStore;
import id.my.hendisantika.oauth2pkcedemo.service.DpopNonceService;
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
 * Time: 23.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class DpopNonceController {

    /** Registered for the probe's client; the probe reads the code off the redirect itself. */
    public static final String CALLBACK_URI = "/dpop-nonce/callback";

    private static final String RUN_ATTRIBUTE = "dpopNonce.run";

    private final DpopNonceService dpopNonceService;

    @GetMapping("/dpop-nonce")
    public String dpopNoncePage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", dpopNonceService.clientId());
        model.addAttribute("apiUri", dpopNonceService.apiUri());
        model.addAttribute("lifetimeSeconds", DpopNonceStore.LIFETIME.toSeconds());
        return "dpop-nonce";
    }

    @PostMapping("/dpop-nonce")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, dpopNonceService.run());
        } catch (RuntimeException ex) {
            log.debug("DPoP nonce run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("nonceError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/dpop-nonce";
    }

    @GetMapping("/dpop-nonce/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/dpop-nonce";
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.ParRequiredService;
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
 * Date: 16/09/26
 * Time: 22.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class ParRequiredController {

    private static final String RUN_ATTRIBUTE = "parRequired.run";

    private final ParRequiredService parRequiredService;

    @GetMapping("/par-required")
    public String parRequiredPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("requiredClientId", parRequiredService.requiredClient().clientId());
        model.addAttribute("ordinaryClientId", parRequiredService.ordinaryClient().clientId());
        return "par-required";
    }

    @PostMapping("/par-required")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, parRequiredService.run());
        } catch (RuntimeException ex) {
            log.debug("PAR-required run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("parRequiredError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/par-required";
    }

    @GetMapping("/par-required/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/par-required";
    }
}

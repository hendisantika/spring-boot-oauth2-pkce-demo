package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestObjectSigningAlgService;
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
 * Time: 06.10
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestObjectSigningAlgController {

    private static final String RUN_ATTRIBUTE = "requestObjectSigningAlg.run";

    private final RequestObjectSigningAlgService requestObjectSigningAlgService;

    @GetMapping("/jar-alg")
    public String signingAlgPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("defaultClientId",
                requestObjectSigningAlgService.defaultAlgClient().clientId());
        model.addAttribute("ps256ClientId", requestObjectSigningAlgService.ps256Client().clientId());
        return "jar-alg";
    }

    @PostMapping("/jar-alg")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestObjectSigningAlgService.run());
        } catch (RuntimeException ex) {
            log.debug("Request object signing algorithm run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarAlgError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-alg";
    }

    @GetMapping("/jar-alg/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-alg";
    }
}

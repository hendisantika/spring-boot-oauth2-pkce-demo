package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestObjectEncryptionService;
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
 * Date: 15/09/26
 * Time: 23.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestObjectEncryptionController {

    private static final String RUN_ATTRIBUTE = "requestObjectEncryption.run";

    private final RequestObjectEncryptionService requestObjectEncryptionService;

    @GetMapping("/jar-enc")
    public String jarEncryptionPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", requestObjectEncryptionService.clientId());
        model.addAttribute("serverKeyId", requestObjectEncryptionService.serverKeyId());
        model.addAttribute("loginHint", RequestObjectEncryptionService.LOGIN_HINT);
        return "jar-enc";
    }

    @PostMapping("/jar-enc")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestObjectEncryptionService.run());
        } catch (RuntimeException ex) {
            log.debug("Request object encryption run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarEncError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-enc";
    }

    @GetMapping("/jar-enc/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-enc";
    }
}

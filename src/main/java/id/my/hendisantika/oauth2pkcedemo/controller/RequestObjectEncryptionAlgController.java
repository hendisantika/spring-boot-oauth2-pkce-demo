package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestObjectEncryptionAlgService;
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
 * Time: 09.20
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestObjectEncryptionAlgController {

    private static final String RUN_ATTRIBUTE = "requestObjectEncryptionAlg.run";

    private final RequestObjectEncryptionAlgService requestObjectEncryptionAlgService;

    @GetMapping("/jar-enc-alg")
    public String encryptionAlgPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("defaultClientId",
                requestObjectEncryptionAlgService.defaultAlgClient().clientId());
        model.addAttribute("oaep512ClientId",
                requestObjectEncryptionAlgService.oaep512Client().clientId());
        model.addAttribute("rsa15ClientId", requestObjectEncryptionAlgService.rsa15Client().clientId());
        model.addAttribute("serverKeyId", requestObjectEncryptionAlgService.serverKeyId());
        return "jar-enc-alg";
    }

    @PostMapping("/jar-enc-alg")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestObjectEncryptionAlgService.run());
        } catch (RuntimeException ex) {
            log.debug("Request object encryption algorithm run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarEncAlgError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-enc-alg";
    }

    @GetMapping("/jar-enc-alg/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-enc-alg";
    }
}

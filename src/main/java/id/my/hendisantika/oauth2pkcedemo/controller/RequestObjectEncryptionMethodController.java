package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestObjectEncryptionMethodService;
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
 * Time: 12.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestObjectEncryptionMethodController {

    private static final String RUN_ATTRIBUTE = "requestObjectEncryptionMethod.run";

    private final RequestObjectEncryptionMethodService requestObjectEncryptionMethodService;

    @GetMapping("/jar-enc-method")
    public String encryptionMethodPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("defaultClientId",
                requestObjectEncryptionMethodService.defaultEncClient().clientId());
        model.addAttribute("gcmClientId", requestObjectEncryptionMethodService.gcmClient().clientId());
        model.addAttribute("unsupportedClientId",
                requestObjectEncryptionMethodService.unsupportedEncClient().clientId());
        model.addAttribute("encOnlyClientId",
                requestObjectEncryptionMethodService.encOnlyClient().clientId());
        model.addAttribute("unsupportedEnc",
                RequestObjectEncryptionMethodService.UNSUPPORTED.getName());
        return "jar-enc-method";
    }

    @PostMapping("/jar-enc-method")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestObjectEncryptionMethodService.run());
        } catch (RuntimeException ex) {
            log.debug("Request object encryption method run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarEncMethodError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-enc-method";
    }

    @GetMapping("/jar-enc-method/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-enc-method";
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.EncryptionMethodValuesService;
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
 * Date: 19/09/26
 * Time: 08.20
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class EncryptionMethodValuesController {

    private static final String RUN_ATTRIBUTE = "encryptionMethodValues.run";

    private final EncryptionMethodValuesService encryptionMethodValuesService;

    @GetMapping("/jar-enc-method-values")
    public String encryptionMethodValuesPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("advertised", encryptionMethodValuesService.advertised());
        return "jar-enc-method-values";
    }

    @PostMapping("/jar-enc-method-values")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, encryptionMethodValuesService.run());
        } catch (RuntimeException ex) {
            log.debug("Encryption method values run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("encryptionMethodValuesError",
                    String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-enc-method-values";
    }

    @GetMapping("/jar-enc-method-values/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-enc-method-values";
    }
}

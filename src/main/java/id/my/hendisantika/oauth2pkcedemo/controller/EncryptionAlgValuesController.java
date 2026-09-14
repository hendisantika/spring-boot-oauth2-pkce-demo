package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.EncryptionAlgValuesService;
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
 * Date: 18/09/26
 * Time: 20.25
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class EncryptionAlgValuesController {

    private static final String RUN_ATTRIBUTE = "encryptionAlgValues.run";

    private final EncryptionAlgValuesService encryptionAlgValuesService;

    @GetMapping("/jar-enc-alg-values")
    public String encryptionAlgValuesPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("advertised", encryptionAlgValuesService.advertised());
        return "jar-enc-alg-values";
    }

    @PostMapping("/jar-enc-alg-values")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, encryptionAlgValuesService.run());
        } catch (RuntimeException ex) {
            log.debug("Encryption algorithm values run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("encryptionAlgValuesError",
                    String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-enc-alg-values";
    }

    @GetMapping("/jar-enc-alg-values/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-enc-alg-values";
    }
}

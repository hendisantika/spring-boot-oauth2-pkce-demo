package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.service.JarmEncryptionService;
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
 * Time: 17.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class JarmEncryptionController {

    private static final String RUN_ATTRIBUTE = "jarmEncryption.run";

    private final JarmEncryptionService jarmEncryptionService;

    @GetMapping("/jarm-enc")
    public String jarmEncryptionPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("algSetting", JarmResponseFilter.ENCRYPTED_RESPONSE_ALG);
        model.addAttribute("encSetting", JarmResponseFilter.ENCRYPTED_RESPONSE_ENC);
        model.addAttribute("defaultEnc", JarmResponseFilter.DEFAULT_ENCRYPTION_METHOD);
        model.addAttribute("jwkSetUri", JarmClientJwkSetController.JARM_CLIENT_JWK_SET_URI);
        model.addAttribute("signedOnlyClientId", jarmEncryptionService.signedOnlyClientId());
        model.addAttribute("encryptedClientId", jarmEncryptionService.encryptedClientId());
        return "jarm-enc";
    }

    @PostMapping("/jarm-enc")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, jarmEncryptionService.run());
        } catch (RuntimeException ex) {
            log.debug("JARM encryption run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("encError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jarm-enc";
    }

    @GetMapping("/jarm-enc/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jarm-enc";
    }
}

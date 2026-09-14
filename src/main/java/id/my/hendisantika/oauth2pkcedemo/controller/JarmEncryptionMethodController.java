package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.service.JarmEncryptionMethodService;
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
 * Time: 20.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class JarmEncryptionMethodController {

    private static final String RUN_ATTRIBUTE = "jarmEncryptionMethod.run";

    private final JarmEncryptionMethodService jarmEncryptionMethodService;
    private final DemoProperties properties;

    @GetMapping("/jarm-enc-method")
    public String jarmEncryptionMethodPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("setting", JarmResponseFilter.ENCRYPTED_RESPONSE_ENC);
        model.addAttribute("algSetting", JarmResponseFilter.ENCRYPTED_RESPONSE_ALG);
        model.addAttribute("supported", jarmEncryptionMethodService.supported());
        model.addAttribute("defaultMethod", jarmEncryptionMethodService.defaultMethod());
        model.addAttribute("clients", java.util.List.of(
                properties.jarmEncryptedClient().clientId(),
                properties.jarmGcmClient().clientId(),
                properties.jarmUnsupportedEncClient().clientId()));
        return "jarm-enc-method";
    }

    @PostMapping("/jarm-enc-method")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, jarmEncryptionMethodService.run());
        } catch (RuntimeException ex) {
            log.debug("JARM enc run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("encMethodError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jarm-enc-method";
    }

    @GetMapping("/jarm-enc-method/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jarm-enc-method";
    }
}

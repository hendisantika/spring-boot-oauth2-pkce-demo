package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestUriRegistrationService;
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
 * Date: 17/09/26
 * Time: 21.30
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestUriRegistrationController {

    private static final String RUN_ATTRIBUTE = "requestUriRegistration.run";

    private final RequestUriRegistrationService requestUriRegistrationService;

    @GetMapping("/request-uri-registration")
    public String requestUriRegistrationPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", requestUriRegistrationService.client().clientId());
        model.addAttribute("registeredUris", requestUriRegistrationService.registeredUris());
        model.addAttribute("currently", requestUriRegistrationService.requireRegistration());
        return "request-uri-registration";
    }

    @PostMapping("/request-uri-registration")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestUriRegistrationService.run());
        } catch (RuntimeException ex) {
            log.debug("request_uri registration run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("requestUriRegistrationError",
                    String.valueOf(ex.getMessage()));
        }
        return "redirect:/request-uri-registration";
    }

    @GetMapping("/request-uri-registration/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/request-uri-registration";
    }
}

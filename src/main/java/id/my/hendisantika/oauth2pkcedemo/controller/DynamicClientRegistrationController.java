package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.DynamicClientRegistrationService;
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
 * Date: 13/09/26
 * Time: 19.14
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class DynamicClientRegistrationController {

    private static final String RUN_ATTRIBUTE = "registration.run";

    private final DynamicClientRegistrationService registrationService;
    private final DemoProperties properties;

    /**
     * Nothing on this page involves a browser session: registration is one machine talking to
     * another, which is the situation the protocol exists for.
     */
    @GetMapping("/dynamic-registration")
    public String registrationPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("registrationEndpoint", registrationService.registrationEndpoint());
        model.addAttribute("registrarClientId", properties.registrarClient().clientId());
        model.addAttribute("requestedMetadata", registrationService.clientMetadata());
        model.addAttribute("createScope", DynamicClientRegistrationService.CREATE_SCOPE);
        model.addAttribute("readScope", DynamicClientRegistrationService.READ_SCOPE);
        return "dynamic-registration";
    }

    @PostMapping("/dynamic-registration")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, registrationService.run());
        } catch (RuntimeException ex) {
            log.debug("Registration run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("registrationError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/dynamic-registration";
    }

    @GetMapping("/dynamic-registration/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/dynamic-registration";
    }
}

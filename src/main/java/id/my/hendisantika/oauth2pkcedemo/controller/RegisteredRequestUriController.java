package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RegisteredRequestUriService;
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
 * Time: 09.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RegisteredRequestUriController {

    private static final String RUN_ATTRIBUTE = "registeredRequestUri.run";

    private final RegisteredRequestUriService registeredRequestUriService;

    @GetMapping("/request-uris")
    public String requestUrisPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("registrationEndpoint",
                registeredRequestUriService.registrationEndpoint());
        model.addAttribute("contentHash", RegisteredRequestUriService.CONTENT_HASH_FRAGMENT);
        return "request-uris";
    }

    @PostMapping("/request-uris")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, registeredRequestUriService.run());
        } catch (RuntimeException ex) {
            log.debug("request_uris run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("requestUrisError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/request-uris";
    }

    @GetMapping("/request-uris/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/request-uris";
    }
}

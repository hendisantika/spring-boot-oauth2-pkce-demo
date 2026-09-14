package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionJwtResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.service.IntrospectionJwtService;
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
 * Time: 08.15
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class IntrospectionJwtController {

    private static final String RUN_ATTRIBUTE = "introspectionJwt.run";

    private final IntrospectionJwtService introspectionJwtService;

    @GetMapping("/introspection-jwt")
    public String introspectionJwtPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", introspectionJwtService.introspectingClientId());
        model.addAttribute("otherClientId", introspectionJwtService.otherClientId());
        model.addAttribute("endpoint", introspectionJwtService.introspectionEndpoint());
        model.addAttribute("mediaType", IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);
        return "introspection-jwt";
    }

    @PostMapping("/introspection-jwt")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, introspectionJwtService.run());
        } catch (RuntimeException ex) {
            log.debug("Introspection JWT run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("introspectionError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/introspection-jwt";
    }

    @GetMapping("/introspection-jwt/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/introspection-jwt";
    }
}

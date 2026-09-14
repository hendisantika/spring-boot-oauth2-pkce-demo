package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.RequestUriService;
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
 * Date: 14/09/26
 * Time: 19.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestUriController {

    /** Registered for the probe's client; nothing listens on it, the probe reads the redirect. */
    public static final String CALLBACK_URI = "/request-uri/callback";

    private static final String RUN_ATTRIBUTE = "requestUri.run";

    private final RequestUriService requestUriService;
    private final DemoProperties properties;

    @GetMapping("/request-uri")
    public String requestUriPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", requestUriService.clientId());
        model.addAttribute("parEndpoint", properties.issuerUri() + "/oauth2/par");
        model.addAttribute("prefix", RequestUriService.PREFIX);
        model.addAttribute("delimiter", RequestUriService.DELIMITER);
        return "request-uri";
    }

    @PostMapping("/request-uri")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestUriService.run());
        } catch (RuntimeException ex) {
            log.debug("request_uri run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("requestUriError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/request-uri";
    }

    @GetMapping("/request-uri/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/request-uri";
    }
}

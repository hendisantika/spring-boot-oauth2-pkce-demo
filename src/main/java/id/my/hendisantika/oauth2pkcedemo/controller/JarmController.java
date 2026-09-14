package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.JarmService;
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
 * Time: 11.30
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class JarmController {

    /** Registered for the probe's client; the probe reads the response off the redirect itself. */
    public static final String CALLBACK_URI = "/jarm/callback";

    private static final String RUN_ATTRIBUTE = "jarm.run";

    private final JarmService jarmService;

    @GetMapping("/jarm")
    public String jarmPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", jarmService.clientId());
        return "jarm";
    }

    @PostMapping("/jarm")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, jarmService.run());
        } catch (RuntimeException ex) {
            log.debug("JARM run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarmError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jarm";
    }

    @GetMapping("/jarm/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jarm";
    }
}

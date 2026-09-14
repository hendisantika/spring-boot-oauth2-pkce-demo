package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.ServerParRequiredService;
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
 * Time: 08.15
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class ServerParRequiredController {

    private static final String RUN_ATTRIBUTE = "serverParRequired.run";

    private final ServerParRequiredService serverParRequiredService;

    @GetMapping("/par-server-required")
    public String serverParRequiredPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("ordinaryClientId", serverParRequiredService.ordinaryClient().clientId());
        model.addAttribute("lockedClientId", serverParRequiredService.lockedClient().clientId());
        model.addAttribute("currently", serverParRequiredService.requirePushedRequests());
        return "par-server-required";
    }

    @PostMapping("/par-server-required")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, serverParRequiredService.run());
        } catch (RuntimeException ex) {
            log.debug("Server PAR run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("serverParError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/par-server-required";
    }

    @GetMapping("/par-server-required/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/par-server-required";
    }
}

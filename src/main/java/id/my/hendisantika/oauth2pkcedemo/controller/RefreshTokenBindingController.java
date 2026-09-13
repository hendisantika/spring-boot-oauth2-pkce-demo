package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.PendingRefreshBinding;
import id.my.hendisantika.oauth2pkcedemo.service.RefreshTokenBindingService;
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
 * Time: 21.06
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RefreshTokenBindingController {

    private static final String PENDING_ATTRIBUTE = "refreshBinding.pending";
    private static final String RUN_ATTRIBUTE = "refreshBinding.run";

    private final RefreshTokenBindingService refreshTokenBindingService;

    /**
     * Reachable signed out, because the device this stands in for has no session here at all - the
     * approval happens separately, on the activation screen, as it does on the device page.
     */
    @GetMapping("/refresh-binding")
    public String refreshBindingPage(HttpSession session, Model model) {
        model.addAttribute("pending", session.getAttribute(PENDING_ATTRIBUTE));
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", refreshTokenBindingService.clientId());
        model.addAttribute("tokenEndpoint", refreshTokenBindingService.tokenEndpoint());
        return "refresh-binding";
    }

    /** Asks for device codes with a key already in hand, so the tokens can be bound to it. */
    @PostMapping("/refresh-binding/start")
    public String start(HttpSession session, RedirectAttributes redirectAttributes) {
        session.removeAttribute(RUN_ATTRIBUTE);
        try {
            session.setAttribute(PENDING_ATTRIBUTE, refreshTokenBindingService.start());
        } catch (RuntimeException ex) {
            redirectAttributes.addFlashAttribute("bindingError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/refresh-binding";
    }

    /** Redeems the approved device code and then tries to refresh three ways. */
    @PostMapping("/refresh-binding/run")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        PendingRefreshBinding pending = (PendingRefreshBinding) session.getAttribute(PENDING_ATTRIBUTE);
        if (pending == null) {
            return "redirect:/refresh-binding";
        }
        try {
            session.setAttribute(RUN_ATTRIBUTE, refreshTokenBindingService.run(pending));
            session.removeAttribute(PENDING_ATTRIBUTE);
        } catch (RuntimeException ex) {
            log.debug("Refresh binding run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("bindingError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/refresh-binding";
    }

    @GetMapping("/refresh-binding/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(PENDING_ATTRIBUTE);
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/refresh-binding";
    }
}

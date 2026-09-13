package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.PendingMtlsRefresh;
import id.my.hendisantika.oauth2pkcedemo.service.MtlsRefreshService;
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
 * Time: 09.40
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class MtlsRefreshController {

    private static final String PENDING_ATTRIBUTE = "mtlsRefresh.pending";
    private static final String RUN_ATTRIBUTE = "mtlsRefresh.run";

    private final MtlsRefreshService mtlsRefreshService;

    /**
     * Open to anyone signed in or not, like the other device-grant pages: the client here is a
     * standalone thing holding a certificate, and has no session on this site to speak of.
     */
    @GetMapping("/mtls-refresh")
    public String mtlsRefreshPage(HttpSession session, Model model) {
        model.addAttribute("pending", session.getAttribute(PENDING_ATTRIBUTE));
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", mtlsRefreshService.clientId());
        model.addAttribute("mtlsTokenEndpoint", mtlsRefreshService.mtlsTokenEndpoint());
        model.addAttribute("plainTokenEndpoint", mtlsRefreshService.plainTokenEndpoint());
        model.addAttribute("certificateThumbprint", mtlsRefreshService.certificateThumbprint());
        model.addAttribute("strangerThumbprint", mtlsRefreshService.strangerThumbprint());
        return "mtls-refresh";
    }

    /** Asks for device codes over the TLS listener, presenting the registered certificate. */
    @PostMapping("/mtls-refresh/start")
    public String start(HttpSession session, RedirectAttributes redirectAttributes) {
        session.removeAttribute(RUN_ATTRIBUTE);
        try {
            session.setAttribute(PENDING_ATTRIBUTE, mtlsRefreshService.start());
        } catch (RuntimeException ex) {
            redirectAttributes.addFlashAttribute("mtlsRefreshError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/mtls-refresh";
    }

    /** Redeems the approved device code, then tries to spend the refresh token three ways. */
    @PostMapping("/mtls-refresh/run")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        PendingMtlsRefresh pending = (PendingMtlsRefresh) session.getAttribute(PENDING_ATTRIBUTE);
        if (pending == null) {
            return "redirect:/mtls-refresh";
        }
        try {
            session.setAttribute(RUN_ATTRIBUTE, mtlsRefreshService.run(pending));
            session.removeAttribute(PENDING_ATTRIBUTE);
        } catch (RuntimeException ex) {
            log.debug("mTLS refresh run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("mtlsRefreshError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/mtls-refresh";
    }

    @GetMapping("/mtls-refresh/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(PENDING_ATTRIBUTE);
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/mtls-refresh";
    }
}

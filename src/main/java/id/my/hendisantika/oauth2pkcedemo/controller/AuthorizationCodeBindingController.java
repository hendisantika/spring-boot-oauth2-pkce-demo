package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.CodeBindingRun;
import id.my.hendisantika.oauth2pkcedemo.security.PendingCodeBinding;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationCodeBindingService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthorizationCodeBindingController {

    /** Registered as this client's redirect URI, so codes come back here rather than to Spring's client. */
    public static final String CALLBACK_URI = "/code-binding/callback";

    private static final String PENDING_ATTRIBUTE = "codeBinding.pending";
    private static final String BOUND_RUN_ATTRIBUTE = "codeBinding.bound";
    private static final String UNBOUND_RUN_ATTRIBUTE = "codeBinding.unbound";

    private final AuthorizationCodeBindingService bindingService;
    private final DemoProperties properties;

    /**
     * Reachable signed out: the run signs the user in on its way through the authorization
     * endpoint, which is the point at which the code is issued in the first place.
     */
    @GetMapping("/code-binding")
    public String codeBindingPage(HttpSession session, Model model) {
        model.addAttribute("boundRun", session.getAttribute(BOUND_RUN_ATTRIBUTE));
        model.addAttribute("unboundRun", session.getAttribute(UNBOUND_RUN_ATTRIBUTE));
        model.addAttribute("clientId", properties.codeBindingClient().clientId());
        model.addAttribute("clientName", properties.codeBindingClient().clientName());
        model.addAttribute("redirectUri", properties.issuerUri() + CALLBACK_URI);
        return "code-binding";
    }

    /**
     * Starts one authorization request by hand rather than through Spring's OAuth2 client, which
     * has no notion of {@code dpop_jkt} and would drop it.
     */
    @GetMapping("/code-binding/start")
    public String start(@RequestParam(defaultValue = "true") boolean bind, HttpSession session) {
        PendingCodeBinding pending = bindingService.start(bind);
        session.setAttribute(PENDING_ATTRIBUTE, pending);
        log.debug("Starting a {} authorization request", bind ? "bound" : "unbound");
        return "redirect:" + bindingService.authorizationUri(pending);
    }

    /**
     * Where the authorization code lands. The code is redeemed several ways here and the outcomes
     * kept for the page; nothing about the run outlives the session.
     */
    @GetMapping(CALLBACK_URI)
    public String callback(@RequestParam(required = false) String code,
                           @RequestParam(required = false) String state,
                           @RequestParam(required = false) String error,
                           HttpSession session,
                           RedirectAttributes redirectAttributes) {
        PendingCodeBinding pending = (PendingCodeBinding) session.getAttribute(PENDING_ATTRIBUTE);
        session.removeAttribute(PENDING_ATTRIBUTE);

        if (error != null) {
            redirectAttributes.addFlashAttribute("bindingError",
                    "The authorization server refused the request: " + error);
            return "redirect:/code-binding";
        }
        if (pending == null || code == null) {
            redirectAttributes.addFlashAttribute("bindingError",
                    "No authorization request is in progress in this session. Start one below.");
            return "redirect:/code-binding";
        }
        if (!pending.state().equals(state)) {
            // The one check the client owes itself: a response that does not answer the request it
            // sent is not a response to it.
            redirectAttributes.addFlashAttribute("bindingError",
                    "The state parameter did not match the one sent with the authorization request.");
            return "redirect:/code-binding";
        }

        CodeBindingRun run = bindingService.redeem(pending, code);
        session.setAttribute(pending.bound() ? BOUND_RUN_ATTRIBUTE : UNBOUND_RUN_ATTRIBUTE, run);
        return "redirect:/code-binding";
    }

    @GetMapping("/code-binding/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(BOUND_RUN_ATTRIBUTE);
        session.removeAttribute(UNBOUND_RUN_ATTRIBUTE);
        session.removeAttribute(PENDING_ATTRIBUTE);
        return "redirect:/code-binding";
    }
}

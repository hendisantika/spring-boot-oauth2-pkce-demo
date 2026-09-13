package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.MixUpRun;
import id.my.hendisantika.oauth2pkcedemo.security.PendingMixUp;
import id.my.hendisantika.oauth2pkcedemo.service.MixUpAttackerService;
import id.my.hendisantika.oauth2pkcedemo.service.MixUpService;
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
 * Time: 18.33
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class MixUpController {

    /** The client's redirect URI - registered at the honest server, and known to the attacker. */
    public static final String CALLBACK_URI = "/mixup/callback";

    private static final String PENDING_ATTRIBUTE = "mixUp.pending";
    private static final String CHECKED_RUN_ATTRIBUTE = "mixUp.checked";
    private static final String UNCHECKED_RUN_ATTRIBUTE = "mixUp.unchecked";

    private final MixUpService mixUpService;
    private final MixUpAttackerService attacker;
    private final DemoProperties properties;

    @GetMapping("/mixup")
    public String mixUpPage(HttpSession session, Model model) {
        model.addAttribute("checkedRun", session.getAttribute(CHECKED_RUN_ATTRIBUTE));
        model.addAttribute("uncheckedRun", session.getAttribute(UNCHECKED_RUN_ATTRIBUTE));
        model.addAttribute("honestIssuer", properties.issuerUri());
        model.addAttribute("attackerIssuer", attacker.issuer());
        model.addAttribute("honestClientId", properties.mixUpClient().clientId());
        model.addAttribute("redirectUri", properties.issuerUri() + CALLBACK_URI);
        model.addAttribute("issParameter", IssuerIdentifierResponseHandler.ISS);
        return "mixup";
    }

    /**
     * The user picks an authorization server and the client sends them to it. This one happens to
     * be the attacker's; the client has no way of knowing that yet, and does not need to - the
     * question is only whether it can tell who answers.
     */
    @GetMapping("/mixup/start")
    public String start(@RequestParam(defaultValue = "true") boolean check, HttpSession session) {
        PendingMixUp pending = mixUpService.start(check);
        session.setAttribute(PENDING_ATTRIBUTE, pending);
        log.debug("Starting a mix-up run, client {} the issuer", check ? "checks" : "ignores");
        return "redirect:" + mixUpService.authorizationUri(pending);
    }

    /**
     * Where the authorization code lands - sent by the honest server, to a client waiting for an
     * answer from somewhere else entirely.
     */
    @GetMapping(CALLBACK_URI)
    public String callback(@RequestParam(required = false) String code,
                           @RequestParam(required = false) String state,
                           @RequestParam(required = false) String error,
                           @RequestParam(name = IssuerIdentifierResponseHandler.ISS, required = false) String iss,
                           HttpSession session,
                           RedirectAttributes redirectAttributes) {
        PendingMixUp pending = (PendingMixUp) session.getAttribute(PENDING_ATTRIBUTE);
        session.removeAttribute(PENDING_ATTRIBUTE);

        if (error != null) {
            redirectAttributes.addFlashAttribute("mixUpError",
                    "The authorization server refused the request: " + error);
            return "redirect:/mixup";
        }
        if (pending == null || code == null) {
            redirectAttributes.addFlashAttribute("mixUpError",
                    "No run is in progress in this session. Start one below.");
            return "redirect:/mixup";
        }
        if (!pending.belongsTo(state)) {
            redirectAttributes.addFlashAttribute("mixUpError",
                    "The state did not match. Worth noting: state survives this attack intact, "
                            + "because the attacker forwarded the client's own value.");
            return "redirect:/mixup";
        }

        MixUpRun run = mixUpService.redeem(pending, code, iss);
        session.setAttribute(pending.checkIssuer() ? CHECKED_RUN_ATTRIBUTE : UNCHECKED_RUN_ATTRIBUTE, run);
        return "redirect:/mixup";
    }

    @GetMapping("/mixup/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(CHECKED_RUN_ATTRIBUTE);
        session.removeAttribute(UNCHECKED_RUN_ATTRIBUTE);
        session.removeAttribute(PENDING_ATTRIBUTE);
        return "redirect:/mixup";
    }
}

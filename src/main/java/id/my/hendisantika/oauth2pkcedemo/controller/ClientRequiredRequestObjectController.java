package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.ClientRequiredRequestObjectService;
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
 * Date: 16/09/26
 * Time: 20.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientRequiredRequestObjectController {

    private static final String RUN_ATTRIBUTE = "clientRequiredRequestObject.run";

    private final ClientRequiredRequestObjectService clientRequiredRequestObjectService;

    @GetMapping("/jar-client-required")
    public String clientRequiredPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("unlockedClientId",
                clientRequiredRequestObjectService.unlockedClient().clientId());
        model.addAttribute("registrationEndpoint",
                clientRequiredRequestObjectService.registrationEndpoint());
        model.addAttribute("serverRequires",
                clientRequiredRequestObjectService.serverRequiresSignedRequestObjects());
        return "jar-client-required";
    }

    @PostMapping("/jar-client-required")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, clientRequiredRequestObjectService.run());
        } catch (RuntimeException ex) {
            log.debug("Client-required request object run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarClientRequiredError",
                    String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-client-required";
    }

    @GetMapping("/jar-client-required/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-client-required";
    }
}

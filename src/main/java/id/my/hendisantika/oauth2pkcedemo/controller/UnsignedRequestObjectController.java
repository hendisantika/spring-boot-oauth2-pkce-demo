package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.UnsignedRequestObjectService;
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
 * Time: 14.30
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class UnsignedRequestObjectController {

    private static final String RUN_ATTRIBUTE = "unsignedRequestObject.run";

    private final UnsignedRequestObjectService unsignedRequestObjectService;

    @GetMapping("/jar-none")
    public String unsignedPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("noneClientId", unsignedRequestObjectService.noneClient().clientId());
        model.addAttribute("strictClientId", unsignedRequestObjectService.strictClient().clientId());
        model.addAttribute("signingClientId", unsignedRequestObjectService.signingClient().clientId());
        model.addAttribute("serverRequiresSigned",
                unsignedRequestObjectService.serverRequiresSignedRequestObjects());
        return "jar-none";
    }

    @PostMapping("/jar-none")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, unsignedRequestObjectService.run());
        } catch (RuntimeException ex) {
            log.debug("Unsigned request object run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarNoneError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-none";
    }

    @GetMapping("/jar-none/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-none";
    }
}

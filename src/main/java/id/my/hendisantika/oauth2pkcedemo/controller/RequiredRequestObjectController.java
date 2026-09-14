package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequiredRequestObjectService;
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
 * Time: 17.20
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequiredRequestObjectController {

    private static final String RUN_ATTRIBUTE = "requiredRequestObject.run";

    private final RequiredRequestObjectService requiredRequestObjectService;

    @GetMapping("/jar-required")
    public String requiredPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("ordinaryClientId",
                requiredRequestObjectService.ordinaryClient().clientId());
        model.addAttribute("noneClientId", requiredRequestObjectService.noneClient().clientId());
        model.addAttribute("strictClientId", requiredRequestObjectService.strictClient().clientId());
        model.addAttribute("currently", requiredRequestObjectService.requireSignedRequestObject());
        return "jar-required";
    }

    @PostMapping("/jar-required")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requiredRequestObjectService.run());
        } catch (RuntimeException ex) {
            log.debug("Required request object run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarRequiredError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-required";
    }

    @GetMapping("/jar-required/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-required";
    }
}

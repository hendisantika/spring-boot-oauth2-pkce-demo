package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.AdvertisedAlgService;
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
 * Date: 18/09/26
 * Time: 15.10
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class AdvertisedAlgController {

    private static final String RUN_ATTRIBUTE = "advertisedAlg.run";

    private final AdvertisedAlgService advertisedAlgService;

    @GetMapping("/jar-alg-values")
    public String advertisedAlgPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("published", advertisedAlgService.published());
        return "jar-alg-values";
    }

    @PostMapping("/jar-alg-values")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, advertisedAlgService.run());
        } catch (RuntimeException ex) {
            log.debug("Advertised algorithm run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("advertisedAlgError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jar-alg-values";
    }

    @GetMapping("/jar-alg-values/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jar-alg-values";
    }
}

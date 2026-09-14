package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.service.JarmAlgorithmService;
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
 * Time: 14.20
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class JarmAlgorithmController {

    private static final String RUN_ATTRIBUTE = "jarmAlgorithm.run";

    private final JarmAlgorithmService jarmAlgorithmService;
    private final DemoProperties properties;

    @GetMapping("/jarm-alg")
    public String jarmAlgorithmPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("setting", JarmResponseFilter.SIGNED_RESPONSE_ALG);
        model.addAttribute("supported", JarmResponseFilter.SUPPORTED_ALGORITHMS);
        model.addAttribute("defaultAlgorithm", JarmResponseFilter.DEFAULT_ALGORITHM);
        model.addAttribute("clients", java.util.List.of(properties.jarmClient().clientId(),
                properties.jarmEcClient().clientId(), properties.jarmNoneClient().clientId()));
        return "jarm-alg";
    }

    @PostMapping("/jarm-alg")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, jarmAlgorithmService.run());
        } catch (RuntimeException ex) {
            log.debug("JARM algorithm run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("algError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jarm-alg";
    }

    @GetMapping("/jarm-alg/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jarm-alg";
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.RequestUriMetadataService;
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
 * Time: 16.05
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class RequestUriMetadataController {

    private static final String RUN_ATTRIBUTE = "requestUriMetadata.run";

    private final RequestUriMetadataService requestUriMetadataService;

    @GetMapping("/request-uri-metadata")
    public String requestUriMetadataPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", requestUriMetadataService.client().clientId());
        model.addAttribute("published", requestUriMetadataService.published());
        model.addAttribute("defaults", requestUriMetadataService.defaultsIfOmitted());
        return "request-uri-metadata";
    }

    @PostMapping("/request-uri-metadata")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, requestUriMetadataService.run());
        } catch (RuntimeException ex) {
            log.debug("request_uri metadata run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("requestUriMetadataError",
                    String.valueOf(ex.getMessage()));
        }
        return "redirect:/request-uri-metadata";
    }

    @GetMapping("/request-uri-metadata/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/request-uri-metadata";
    }
}

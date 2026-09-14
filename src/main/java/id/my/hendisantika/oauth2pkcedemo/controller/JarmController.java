package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.service.JarmService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 11.30
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class JarmController {

    /** Registered for the probe's client; the probe reads the response off the redirect itself. */
    public static final String CALLBACK_URI = "/jarm/callback";

    private static final String RUN_ATTRIBUTE = "jarm.run";

    private final JarmService jarmService;

    @GetMapping("/jarm")
    public String jarmPage(HttpSession session, Model model) {
        model.addAttribute("run", session.getAttribute(RUN_ATTRIBUTE));
        model.addAttribute("clientId", jarmService.clientId());
        return "jarm";
    }

    @PostMapping("/jarm")
    public String run(HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            session.setAttribute(RUN_ATTRIBUTE, jarmService.run());
        } catch (RuntimeException ex) {
            log.debug("JARM run failed: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("jarmError", String.valueOf(ex.getMessage()));
        }
        return "redirect:/jarm";
    }

    /**
     * Where a form_post.jwt response actually arrives. The other modes put the answer in the URL and
     * the browser follows a redirect; this one submits a form, so the client reads its own request
     * body - which is the entire difference between the two.
     */
    @PostMapping(CALLBACK_URI)
    @ResponseBody
    public Map<String, Object> callback(
            @RequestParam(name = JarmResponseFilter.RESPONSE, required = false) String response) {
        Map<String, Object> received = new LinkedHashMap<>();
        received.put("delivered_in", "the request body");
        received.put("characters", response == null ? 0 : response.length());
        received.put("response", response);
        return received;
    }

    @GetMapping("/jarm/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(RUN_ATTRIBUTE);
        return "redirect:/jarm";
    }
}

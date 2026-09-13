package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.CibaClientService;
import id.my.hendisantika.oauth2pkcedemo.service.CibaService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
@Controller
@RequiredArgsConstructor
public class CibaController {

    static final String AUTH_REQ_ID_ATTRIBUTE = "ciba.authReqId";

    private final CibaClientService cibaClientService;
    private final CibaService cibaService;
    private final DemoProperties properties;

    /**
     * Stands in for the client's backend. Public, because the whole point is that the user never
     * comes here — they are named by a hint and approve on a device of their own.
     */
    @GetMapping("/ciba")
    public String cibaPage(HttpSession session, Model model) {
        model.addAttribute("clientId", properties.cibaClient().clientId());
        model.addAttribute("scopes", String.join(" ", properties.cibaClient().scopes()));
        model.addAttribute("demoUsers", properties.demoUsers());
        model.addAttribute("authReqId", session.getAttribute(AUTH_REQ_ID_ATTRIBUTE));
        model.addAttribute("interval", CibaService.POLL_INTERVAL_SECONDS);
        return "ciba";
    }

    @PostMapping("/ciba")
    public String start(@RequestParam("login_hint") String loginHint,
                        @RequestParam("binding_message") String bindingMessage,
                        HttpSession session, Model model) {
        Map<String, Object> response = cibaClientService.requestAuthentication(loginHint, bindingMessage);
        if (response != null && response.containsKey("auth_req_id")) {
            session.setAttribute(AUTH_REQ_ID_ATTRIBUTE, response.get("auth_req_id"));
            session.setAttribute("ciba.bindingMessage", bindingMessage);
            session.setAttribute("ciba.loginHint", loginHint);
        } else {
            session.setAttribute("ciba.error", response == null ? "no response"
                    : String.valueOf(response.get("error_description")));
        }
        return "redirect:/ciba";
    }

    @PostMapping("/ciba/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(AUTH_REQ_ID_ATTRIBUTE);
        session.removeAttribute("ciba.bindingMessage");
        session.removeAttribute("ciba.error");
        return "redirect:/ciba";
    }

    /** One poll, so the page can loop the way the client's backend would. */
    @PostMapping("/ciba/poll")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> poll(HttpSession session) {
        Object authReqId = session.getAttribute(AUTH_REQ_ID_ATTRIBUTE);
        if (authReqId == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "NONE"));
        }
        CibaClientService.PollResult result = cibaClientService.poll(String.valueOf(authReqId));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", result.status());
        body.put("error", result.error());
        body.put("accessToken", result.accessTokenFingerprint());
        return ResponseEntity.ok(body);
    }

    /**
     * The approving device. Signed in as the user, this lists what is waiting for them and shows the
     * binding message so they can check it against what the client displayed.
     */
    @GetMapping("/ciba/approve")
    public String approvals(Authentication authentication, Model model) {
        model.addAttribute("pending", cibaService.pendingFor(authentication.getName()));
        return "ciba-approve";
    }

    @PostMapping("/ciba/approve")
    public String decide(Authentication authentication,
                         @RequestParam("auth_req_id") String authReqId,
                         @RequestParam("decision") String decision) {
        cibaService.decide(authReqId, authentication.getName(), "approve".equals(decision));
        return "redirect:/ciba/approve";
    }
}

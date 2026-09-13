package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequestResolver;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.16
 */
@Controller
@RequiredArgsConstructor
public class PushedAuthorizationController {

    private final DemoProperties properties;

    /**
     * Reachable signed out: pushing the request is the first step of logging in, not something you
     * do once you already have a session.
     */
    @GetMapping("/par")
    public String parPage(HttpSession session, Model model) {
        model.addAttribute("pushed", PushedAuthorizationRequestResolver.lastPushed(session));
        model.addAttribute("parLoginUri",
                "/oauth2/authorization/" + properties.confidentialClient().registrationId());
        model.addAttribute("plainLoginUri",
                "/oauth2/authorization/" + properties.client().registrationId());
        model.addAttribute("parEndpoint", properties.issuerUri() + "/oauth2/par");
        model.addAttribute("confidentialClientName", properties.confidentialClient().clientName());
        model.addAttribute("publicClientName", properties.client().clientName());
        return "par";
    }
}

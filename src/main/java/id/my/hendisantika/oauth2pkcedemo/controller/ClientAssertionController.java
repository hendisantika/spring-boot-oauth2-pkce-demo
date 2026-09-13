package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.ClientAssertionService;
import lombok.RequiredArgsConstructor;
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
 * Date: 13/09/26
 * Time: 14.42
 */
@Controller
@RequiredArgsConstructor
public class ClientAssertionController {

    private final ClientAssertionService clientAssertionService;
    private final DemoProperties properties;

    /**
     * Public, like the other pages that start rather than continue a flow: there is no user in this
     * exchange, only a client proving who it is.
     */
    @GetMapping("/assertion")
    public String assertionPage(Model model) {
        model.addAttribute("clientId", properties.assertionClient().clientId());
        model.addAttribute("clientName", properties.assertionClient().clientName());
        model.addAttribute("scopes", String.join(" ", properties.assertionClient().scopes()));
        model.addAttribute("tokenEndpoint", clientAssertionService.tokenEndpoint());
        model.addAttribute("jwkSetUrl", clientAssertionService.jwkSetUrl());
        model.addAttribute("publicJwkSet", clientAssertionService.publicJwkSet());
        model.addAttribute("assertionType", ClientAssertionService.JWT_BEARER_ASSERTION_TYPE);
        return "assertion";
    }

    @PostMapping("/assertion")
    public String run(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("attempts", clientAssertionService.run());
        return "redirect:/assertion";
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.service.MixUpAttackerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 18.33
 */
@Controller
@RequiredArgsConstructor
public class MixUpAttackerController {

    private final MixUpAttackerService attacker;

    /**
     * The attacker's authorization endpoint. A real one would look like any other - it is a
     * perfectly ordinary authorization server that the user or the client had some reason to
     * accept. What it does with the request is the attack.
     */
    @GetMapping("/mixup/attacker/authorize")
    public RedirectView authorize(@RequestParam Map<String, String> parameters) {
        return new RedirectView(attacker.mixUpRedirect(parameters));
    }

    /**
     * The attacker's token endpoint, and the only thing it ever needed: a client that cannot tell
     * who answered will bring the authorization code here by itself.
     */
    @PostMapping("/mixup/attacker/token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam(OAuth2ParameterNames.CODE) String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam(OAuth2ParameterNames.REDIRECT_URI) String redirectUri) {
        Map<String, Object> response = new LinkedHashMap<>(
                attacker.receiveStolenCode(code, codeVerifier, redirectUri));
        // A real attacker answers with something that keeps the client quiet. This one says what it
        // took, because the page has to be able to show it.
        response.put("error", "invalid_grant");
        return ResponseEntity.ok(response);
    }
}

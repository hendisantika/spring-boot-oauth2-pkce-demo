package id.my.hendisantika.oauth2pkcedemo.controller;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.20
 */
@RestController
public class StrongResourceController {

    public static final String TRANSFER_URI = "/resource/transfer";

    /**
     * Stands in for the operation nobody minds authenticating twice for. Reaching the method at all
     * means the token carried the required {@code acr}; everything weaker was answered by the
     * challenge before this ran.
     */
    @PostMapping(value = TRANSFER_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> transfer(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("transferred", "1,000.00");
        body.put("sub", jwt.getSubject());
        body.put("acr", jwt.getClaimAsString("acr"));
        body.put("amr", jwt.getClaim("amr"));
        return body;
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.24
 */
@RestController
public class ProtectedApiController {

    /**
     * A resource server endpoint that accepts nothing but a DPoP-bound token. Reaching it proves the
     * caller holds the private key the token was bound to, not merely the token.
     */
    @GetMapping(value = "/api/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("aud", jwt.getAudience());
        body.put("scope", jwt.getClaimAsString("scope"));
        // The confirmation claim: the thumbprint of the key this token is tied to.
        body.put("cnf", jwt.getClaim("cnf"));
        return body;
    }
}

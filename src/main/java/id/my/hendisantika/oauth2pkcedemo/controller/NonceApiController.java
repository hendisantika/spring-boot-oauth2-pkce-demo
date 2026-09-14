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
 * Date: 14/09/26
 * Time: 23.05
 */
@RestController
public class NonceApiController {

    public static final String NONCE_API_URI = "/nonce/me";

    /**
     * Reaching this means the caller held the private key <em>and</em> had been given a nonce by
     * this server since the last one it used - so the proof cannot have been made in advance.
     */
    @GetMapping(value = NONCE_API_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("cnf", jwt.getClaim("cnf"));
        return body;
    }
}

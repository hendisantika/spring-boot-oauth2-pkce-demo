package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.ClientAssertionKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.42
 */
@RestController
@RequiredArgsConstructor
public class ClientJwkSetController {

    public static final String CLIENT_JWK_SET_URI = "/client-jwks.json";

    private final ClientAssertionKey clientAssertionKey;

    /**
     * The client publishes its public keys here and the authorization server fetches them when it
     * has an assertion to verify. Rotating the key is then a matter of publishing a new one - there
     * is no shared secret to coordinate.
     */
    @GetMapping(value = CLIENT_JWK_SET_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwkSet() {
        return clientAssertionKey.publicJwkSetJson();
    }
}

package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
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
 * Time: 17.15
 */
@RestController
@RequiredArgsConstructor
public class JarJwkSetController {

    public static final String JAR_JWK_SET_URI = "/jar-jwks.json";

    private final JarRequestSigner jarRequestSigner;

    /** Where the authorization server fetches the key it checks request object signatures against. */
    @GetMapping(value = JAR_JWK_SET_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwkSet() {
        return jarRequestSigner.publicJwkSetJson();
    }
}

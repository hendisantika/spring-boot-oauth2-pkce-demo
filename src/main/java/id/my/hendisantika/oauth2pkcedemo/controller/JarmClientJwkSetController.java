package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.JarmClientKeys;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 17.05
 */
@Controller
@RequiredArgsConstructor
public class JarmClientJwkSetController {

    public static final String JARM_CLIENT_JWK_SET_URI = "/jarm-client-jwks.json";

    private final JarmClientKeys jarmClientKeys;

    /**
     * Where the authorization server fetches the key it encrypts this client's authorization
     * responses to. Published unauthenticated, because a public key is not a secret and the server
     * has to be able to read it before anyone has authenticated anything.
     */
    @GetMapping(value = JARM_CLIENT_JWK_SET_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public String jwkSet() {
        return jarmClientKeys.publicJwkSetJson();
    }
}

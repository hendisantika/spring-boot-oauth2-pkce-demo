package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
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
 * Time: 15.02
 */
@RestController
@RequiredArgsConstructor
public class MtlsJwkSetController {

    public static final String MTLS_JWK_SET_URI = "/mtls-jwks.json";

    private final MtlsMaterial mtlsMaterial;

    /**
     * The client's certificate, published as a JWK with an x5c chain. Spring Authorization Server
     * verifies a self-signed client certificate by fetching this and looking for a key whose chain
     * matches what arrived on the TLS handshake.
     */
    @GetMapping(value = MTLS_JWK_SET_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwkSet() {
        return mtlsMaterial.clientJwkSetJson();
    }
}

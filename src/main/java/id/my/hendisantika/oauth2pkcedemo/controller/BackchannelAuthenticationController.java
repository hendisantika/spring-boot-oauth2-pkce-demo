package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.entity.CibaRequest;
import id.my.hendisantika.oauth2pkcedemo.service.CibaService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
@RestController
@RequiredArgsConstructor
public class BackchannelAuthenticationController {

    public static final String BACKCHANNEL_AUTHENTICATION_URI = "/backchannel/authenticate";

    private final CibaService cibaService;
    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * The CIBA backchannel authentication endpoint. Spring Authorization Server has no notion of it,
     * so it is a plain controller — including the client authentication, which the framework would
     * otherwise have done through {@code OAuth2ClientAuthenticationFilter}. A real implementation
     * would register the endpoint with the framework rather than checking Basic auth by hand.
     */
    @PostMapping(value = BACKCHANNEL_AUTHENTICATION_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> authenticate(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam("scope") String scope,
            @RequestParam("login_hint") String loginHint,
            @RequestParam(value = "binding_message", required = false) String bindingMessage) {

        RegisteredClient client = authenticateClient(authorization);
        if (client == null) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_client",
                    "The client did not authenticate");
        }
        if (!client.getScopes().containsAll(java.util.Set.of(scope.split(" ")))) {
            return error(HttpStatus.BAD_REQUEST, "invalid_scope",
                    "The client is not registered for " + scope);
        }

        CibaRequest request;
        try {
            request = cibaService.start(client.getClientId(), loginHint, scope, bindingMessage);
        } catch (IllegalArgumentException ex) {
            // CIBA Core section 13: the hint has to resolve to exactly one user.
            return error(HttpStatus.BAD_REQUEST, "unknown_user_id", ex.getMessage());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("auth_req_id", request.getAuthReqId());
        body.put("expires_in", CibaService.LIFETIME.toSeconds());
        body.put("interval", CibaService.POLL_INTERVAL_SECONDS);
        return ResponseEntity.status(HttpStatus.OK).body(body);
    }

    private RegisteredClient authenticateClient(String authorization) {
        if (authorization == null || !authorization.startsWith("Basic ")) {
            return null;
        }
        String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)),
                StandardCharsets.UTF_8);
        int separator = decoded.indexOf(':');
        if (separator < 0) {
            return null;
        }
        RegisteredClient client = registeredClientRepository.findByClientId(decoded.substring(0, separator));
        if (client == null
                || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                || client.getClientSecret() == null
                || !passwordEncoder.matches(decoded.substring(separator + 1), client.getClientSecret())) {
            return null;
        }
        return client;
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String error,
                                                             String description) {
        return ResponseEntity.status(status)
                .body(Map.of("error", error, "error_description", description));
    }
}

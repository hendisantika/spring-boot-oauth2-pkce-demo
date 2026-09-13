package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.ClientAssertionAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.ClientAssertionKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.42
 */
@Slf4j
@Service
public class ClientAssertionService {

    /** RFC 7523 section 2.2: the value that tells the token endpoint what kind of assertion it is. */
    public static final String JWT_BEARER_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final RestClient restClient;
    private final ClientAssertionKey clientAssertionKey;
    private final DemoProperties properties;

    public ClientAssertionService(ClientAssertionKey clientAssertionKey, DemoProperties properties) {
        this.clientAssertionKey = clientAssertionKey;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public String tokenEndpoint() {
        return properties.issuerUri() + "/oauth2/token";
    }

    public String jwkSetUrl() {
        return properties.issuerUri() + "/client-jwks.json";
    }

    public String publicJwkSet() {
        return clientAssertionKey.publicJwkSetJson();
    }

    /**
     * Asks for a token three times: correctly, with an assertion signed by a key the server has
     * never seen, and with one that expired before it was sent.
     */
    public List<ClientAssertionAttempt> run() {
        String clientId = properties.assertionClient().clientId();
        String audience = tokenEndpoint();

        return List.of(
                attempt("A valid assertion",
                        "Signed with the key published at the client's jwkSetUrl.",
                        clientAssertionKey.assertion(clientId, audience, Duration.ofMinutes(2))),
                attempt("Signed by the wrong key",
                        "Correct claims, but signed with a key the server has never seen.",
                        clientAssertionKey.assertionSignedByAnotherKey(clientId, audience, Duration.ofMinutes(2))),
                attempt("Already expired",
                        "Signed with the right key, but exp is in the past.",
                        clientAssertionKey.assertion(clientId, audience, Duration.ofMinutes(-2))));
    }

    private ClientAssertionAttempt attempt(String label, String description, String assertion) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", String.join(" ", properties.assertionClient().scopes()));
        form.add("client_assertion_type", JWT_BEARER_ASSERTION_TYPE);
        form.add("client_assertion", assertion);
        // RFC 7523 treats client_id as optional here, since the assertion's iss and sub already name
        // the client - but Spring Authorization Server's converter requires it, and answers
        // invalid_request without it.
        form.add("client_id", properties.assertionClient().clientId());

        return restClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    String body = response.bodyTo(String.class);
                    log.debug("Client assertion attempt [{}] -> {}", label, response.getStatusCode());
                    return new ClientAssertionAttempt(label, description, claimsOf(assertion),
                            response.getStatusCode().value(),
                            body == null || body.isBlank() ? "(empty)" : body);
                }, false);
    }

    private static Map<String, Object> claimsOf(String jwt) {
        try {
            return new TreeMap<>(JWTParser.parse(jwt).getJWTClaimsSet().getClaims());
        } catch (ParseException ex) {
            return Map.of("error", "Unable to parse: " + ex.getMessage());
        }
    }
}

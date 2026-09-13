package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.TokenExchangeAttempt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
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
 * Time: 15.04
 */
@Slf4j
@Service
public class TokenExchangeService {

    public static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final RestClient restClient;
    private final DemoProperties properties;

    public TokenExchangeService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * Runs the two shapes RFC 8693 distinguishes, plus one that must fail.
     *
     * @param subjectToken the user's access token, as a downstream service would have received it
     */
    public List<TokenExchangeAttempt> run(String subjectToken) {
        List<TokenExchangeAttempt> attempts = new ArrayList<>();

        attempts.add(exchange("Impersonation",
                "The service asks for a token of its own for this user. No actor token, so nothing "
                        + "records that the service was involved.",
                impersonationParameters(subjectToken)));

        String actorToken = clientCredentialsToken();
        if (actorToken != null) {
            Map<String, String> delegation = impersonationParameters(subjectToken);
            delegation.put("actor_token", actorToken);
            delegation.put("actor_token_type", ACCESS_TOKEN_TYPE);
            attempts.add(exchange("Delegation",
                    "The same exchange, with the service's own token attached as the actor. The "
                            + "result carries an act claim naming who is acting.",
                    delegation));
        }

        Map<String, String> beyondScope = impersonationParameters(subjectToken);
        beyondScope.put("scope", "api.read api.write admin.everything");
        attempts.add(exchange("Asking for more than it may have",
                "Same subject token, but requesting a scope the client is not registered for.",
                beyondScope));

        return attempts;
    }

    private Map<String, String> impersonationParameters(String subjectToken) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("grant_type", TOKEN_EXCHANGE_GRANT);
        parameters.put("subject_token", subjectToken);
        parameters.put("subject_token_type", ACCESS_TOKEN_TYPE);
        // Narrower than what the subject token carries: the downstream service gets only what it
        // needs, not everything the user granted the front end.
        parameters.put("scope", "api.read");
        return parameters;
    }

    /** The exchange client's own identity, used as the actor in the delegation case. */
    @SuppressWarnings("unchecked")
    private String clientCredentialsToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "api.read");
        try {
            Map<String, Object> body = restClient.post()
                    .uri("/oauth2/token")
                    .header("Authorization", basicAuthHeader())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            return body == null ? null : (String) body.get("access_token");
        } catch (Exception ex) {
            log.warn("Unable to mint an actor token: {}", ex.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private TokenExchangeAttempt exchange(String label, String description, Map<String, String> parameters) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        parameters.forEach(form::add);

        return restClient.post()
                .uri("/oauth2/token")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    Map<String, Object> body = response.bodyTo(Map.class);
                    int status = response.getStatusCode().value();
                    log.debug("Token exchange [{}] -> {}", label, status);
                    if (status != 200 || body == null) {
                        return new TokenExchangeAttempt(label, description, redact(parameters), status,
                                body == null ? "(empty)" : String.valueOf(body.get("error")), null, null);
                    }
                    return new TokenExchangeAttempt(label, description, redact(parameters), status, null,
                            claimsOf((String) body.get("access_token")),
                            (String) body.get("issued_token_type"));
                }, false);
    }

    /** Tokens are long and are shown decoded elsewhere; the shape of the request is the point here. */
    private static Map<String, String> redact(Map<String, String> parameters) {
        Map<String, String> shown = new LinkedHashMap<>();
        parameters.forEach((name, value) -> shown.put(name,
                name.endsWith("_token") && value.length() > 24
                        ? value.substring(0, 14) + "…" + value.substring(value.length() - 6)
                        : value));
        return shown;
    }

    private static Map<String, Object> claimsOf(String jwt) {
        try {
            return new TreeMap<>(JWTParser.parse(jwt).getJWTClaimsSet().getClaims());
        } catch (ParseException ex) {
            return Map.of("error", "Unable to parse: " + ex.getMessage());
        }
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.exchangeClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.BackchannelAuthenticationController;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationConverter;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
@Slf4j
@Service
public class CibaClientService {

    /** One poll of the token endpoint, shaped for the page's JavaScript. */
    public record PollResult(String status, String error, String accessTokenFingerprint) {
    }

    private final RestClient restClient;
    private final DemoProperties properties;

    public CibaClientService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** Opens the backchannel request, as the client would from its own backend. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> requestAuthentication(String loginHint, String bindingMessage) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("scope", String.join(" ", properties.cibaClient().scopes()));
        form.add("login_hint", loginHint);
        form.add("binding_message", bindingMessage);

        return restClient.post()
                .uri(BackchannelAuthenticationController.BACKCHANNEL_AUTHENTICATION_URI)
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);
    }

    /**
     * Polls for the outcome. {@code authorization_pending} is the normal answer until the user acts,
     * so it is reported as a state rather than raised as a failure.
     */
    @SuppressWarnings("unchecked")
    public PollResult poll(String authReqId) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue());
        form.add(CibaAuthenticationConverter.AUTH_REQ_ID, authReqId);

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/token")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);

        if (body == null) {
            return new PollResult("ERROR", "no_response", null);
        }
        if (body.containsKey("error")) {
            String error = String.valueOf(body.get("error"));
            String status = switch (error) {
                case "authorization_pending" -> "PENDING";
                case "access_denied" -> "DENIED";
                case "expired_token" -> "EXPIRED";
                default -> "ERROR";
            };
            return new PollResult(status, error, null);
        }
        String accessToken = String.valueOf(body.get("access_token"));
        log.debug("CIBA poll for {} returned a token", authReqId);
        return new PollResult("GRANTED", null, fingerprint(accessToken));
    }

    private static String fingerprint(String token) {
        return token.length() <= 28 ? token
                : token.substring(0, 16) + "…" + token.substring(token.length() - 10);
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.cibaClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

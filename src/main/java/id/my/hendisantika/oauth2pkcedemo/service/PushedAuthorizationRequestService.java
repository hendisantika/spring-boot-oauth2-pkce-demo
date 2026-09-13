package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.16
 */
@Slf4j
@Service
public class PushedAuthorizationRequestService {

    /** What the authorization server hands back in place of the request itself. */
    public record PushedRequestUri(String requestUri, Duration expiresIn) {
    }

    private final RestClient restClient;
    private final DemoProperties properties;

    public PushedAuthorizationRequestService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * Sends the authorization request to the authorization server over a back channel and takes a
     * handle for it. The endpoint requires client authentication, which is what makes the request
     * tamper-proof: nothing between the browser and the server ever sees the parameters, let alone
     * gets to change them.
     */
    @SuppressWarnings("unchecked")
    public PushedRequestUri push(Map<String, String> parameters) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        parameters.forEach(form::add);

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/par")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        String requestUri = (String) body.get("request_uri");
        long expiresIn = body.get("expires_in") instanceof Number number ? number.longValue() : 60;
        log.debug("Pushed authorization request, request_uri={} expires_in={}s", requestUri, expiresIn);
        return new PushedRequestUri(requestUri, Duration.ofSeconds(expiresIn));
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.confidentialClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

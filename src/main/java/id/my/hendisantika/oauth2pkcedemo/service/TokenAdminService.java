package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionResult;
import id.my.hendisantika.oauth2pkcedemo.security.RevocationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.56
 */
@Slf4j
@Service
public class TokenAdminService {

    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";

    private final RestClient restClient;
    private final DemoProperties properties;

    public TokenAdminService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * RFC 7662. Both endpoints demand an authenticated client, so this uses the confidential
     * client's secret - the public client has nothing to authenticate with, which is why the demo
     * page asks you to sign in as the confidential one.
     */
    @SuppressWarnings("unchecked")
    public IntrospectionResult introspect(String token, String tokenTypeHint) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", tokenTypeHint);

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/introspect")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);

        if (body == null) {
            return IntrospectionResult.of(tokenTypeHint, Map.of("active", false));
        }
        log.debug("Introspected {}: active={}", tokenTypeHint, body.get("active"));
        return IntrospectionResult.of(tokenTypeHint, body);
    }

    /**
     * RFC 7009. Unlike introspection, the authorization server only lets a client revoke tokens it
     * was itself issued - revoking someone else's is answered with {@code invalid_client}.
     */
    public RevocationResult revoke(String token, String tokenTypeHint) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", tokenTypeHint);

        return restClient.post()
                .uri("/oauth2/revoke")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    String error = null;
                    if (status != 200) {
                        Map<?, ?> body = response.bodyTo(Map.class);
                        error = body == null ? "unknown_error" : String.valueOf(body.get("error"));
                    }
                    log.debug("Revoked {}: status={}", tokenTypeHint, status);
                    return new RevocationResult(tokenTypeHint, status, error, Instant.now());
                }, false);
    }

    public String introspectingClientId() {
        return properties.confidentialClient().clientId();
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.confidentialClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

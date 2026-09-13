package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DeviceAuthorization;
import id.my.hendisantika.oauth2pkcedemo.security.DevicePollResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.40
 */
@Slf4j
@Service
public class DeviceFlowService {

    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private final RestClient restClient;
    private final DemoProperties properties;

    public DeviceFlowService(DemoProperties properties) {
        this.properties = properties;
        // Talks to this same application over HTTP on purpose: that is what a real device does, and
        // going through the wire keeps the demo honest about which parameters are actually sent.
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * Step 1 of RFC 8628: the device asks for a pair of codes. It authenticates with nothing but its
     * client id - a device that cannot keep a secret is the whole reason this grant exists.
     */
    @SuppressWarnings("unchecked")
    public DeviceAuthorization requestDeviceAuthorization() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", properties.client().clientId());
        form.add("scope", deviceScopes());

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        int expiresIn = asInt(body.get("expires_in"), 300);
        DeviceAuthorization authorization = new DeviceAuthorization(
                (String) body.get("device_code"),
                (String) body.get("user_code"),
                (String) body.get("verification_uri"),
                (String) body.get("verification_uri_complete"),
                Instant.now().plusSeconds(expiresIn),
                asInt(body.get("interval"), 5),
                Instant.now());
        log.debug("Device authorization issued, user_code={} expires_in={}s",
                authorization.userCode(), expiresIn);
        return authorization;
    }

    /**
     * Step 2: the device polls the token endpoint. Until someone approves the user code this returns
     * HTTP 400 with {@code authorization_pending}, which is a normal part of the flow rather than a
     * failure - hence the explicit status handling instead of letting RestClient raise.
     */
    @SuppressWarnings("unchecked")
    public DevicePollResult poll(DeviceAuthorization authorization) {
        if (authorization.isExpired()) {
            return DevicePollResult.of(DevicePollResult.Status.EXPIRED, "expired_token",
                    "The device code timed out before it was approved.");
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", DEVICE_CODE_GRANT);
        form.add("device_code", authorization.deviceCode());
        form.add("client_id", properties.client().clientId());

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);

        if (body == null) {
            return DevicePollResult.of(DevicePollResult.Status.ERROR, "no_response",
                    "The token endpoint returned an empty body.");
        }
        if (body.containsKey("error")) {
            return fromError((String) body.get("error"), (String) body.get("error_description"));
        }

        Set<String> scopes = body.get("scope") instanceof String scope
                ? new LinkedHashSet<>(Set.of(scope.split(" ")))
                : Set.of();
        return DevicePollResult.granted(
                (String) body.get("access_token"),
                (String) body.get("refresh_token"),
                scopes,
                Instant.now().plusSeconds(asInt(body.get("expires_in"), 0)));
    }

    private static DevicePollResult fromError(String error, String description) {
        return switch (error) {
            case "authorization_pending" -> DevicePollResult.pending(error);
            case "slow_down" -> DevicePollResult.of(DevicePollResult.Status.SLOW_DOWN, error, description);
            case "access_denied" -> DevicePollResult.of(DevicePollResult.Status.DENIED, error, description);
            case "expired_token" -> DevicePollResult.of(DevicePollResult.Status.EXPIRED, error, description);
            default -> DevicePollResult.of(DevicePollResult.Status.ERROR, error, description);
        };
    }

    /**
     * Everything the client is registered for except {@code openid}: Spring Authorization Server
     * rejects that scope on the device authorization grant with {@code invalid_scope}, because
     * OpenID Connect is not defined over this flow - so there is no ID token here, only an access
     * token.
     */
    public String deviceScopes() {
        return properties.client().scopes().stream()
                .filter(scope -> !OidcScopes.OPENID.equals(scope))
                .collect(Collectors.joining(" "));
    }

    private static int asInt(Object value, int fallback) {
        return value instanceof Number number ? number.intValue() : fallback;
    }
}

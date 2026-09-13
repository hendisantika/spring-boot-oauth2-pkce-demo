package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import id.my.hendisantika.oauth2pkcedemo.security.PendingRefreshBinding;
import id.my.hendisantika.oauth2pkcedemo.security.RefreshBindingAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RefreshBindingRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 21.06
 */
@Slf4j
@Service
public class RefreshTokenBindingService {

    private static final String DPOP_HEADER = "DPoP";
    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private final RestClient restClient;
    private final DemoProperties properties;

    public RefreshTokenBindingService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public String clientId() {
        return properties.client().clientId();
    }

    public String tokenEndpoint() {
        return properties.issuerUri() + "/oauth2/token";
    }

    /**
     * Starts a device authorization for the public client, with a key generated first. The device
     * grant is used because it is the one place this server issues a refresh token to a client that
     * holds no credentials - which is exactly the case RFC 9449 section 5 has rules about.
     */
    @SuppressWarnings("unchecked")
    public PendingRefreshBinding start() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());
        form.add(OAuth2ParameterNames.SCOPE, "profile email");

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        if (body == null) {
            throw new IllegalStateException("The device authorization endpoint said nothing");
        }
        log.debug("Device authorization for the refresh binding run, user_code={}", body.get("user_code"));
        return new PendingRefreshBinding(String.valueOf(body.get("device_code")),
                String.valueOf(body.get("user_code")), DpopKeyPair.generate(), Instant.now());
    }

    /**
     * Redeems the device code with a proof, then tries to refresh three ways. The first two are what
     * the specification describes; the third is the one worth running.
     */
    @SuppressWarnings("unchecked")
    public RefreshBindingRun run(PendingRefreshBinding pending) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, DEVICE_CODE_GRANT);
        form.add("device_code", pending.deviceCode());
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());

        Map<String, Object> issued = restClient.post()
                .uri("/oauth2/token")
                .header(DPOP_HEADER, pending.key().proof("POST", tokenEndpoint(), null))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);

        if (issued == null || issued.get("access_token") == null) {
            throw new IllegalStateException(issued == null
                    ? "The token endpoint said nothing"
                    : "The device code was not redeemable: " + issued.get("error"));
        }

        String accessToken = String.valueOf(issued.get("access_token"));
        String refreshToken = issued.get(OAuth2ParameterNames.REFRESH_TOKEN) == null
                ? null : String.valueOf(issued.get(OAuth2ParameterNames.REFRESH_TOKEN));

        List<RefreshBindingAttempt> attempts = new ArrayList<>();
        if (refreshToken != null) {
            // Refresh tokens are rotated here, so each attempt is made with whatever the last
            // successful one handed back. Reusing a spent token would fail as invalid_grant and
            // say nothing about the binding at all.
            Refreshing refreshing = new Refreshing(refreshToken);
            attempts.add(refreshing.attempt("With a proof from another key",
                    "A well-formed proof, signed by a key the tokens were never bound to.",
                    DpopKeyPair.generate()));
            attempts.add(refreshing.attempt("With no proof at all",
                    "The refresh token on its own, as a stolen one would be presented.", null));
            attempts.add(refreshing.attempt("With a proof from the bound key",
                    "What the client that was issued the token would send.", pending.key()));
        }

        log.debug("Refresh binding run finished for {}", clientId());
        return new RefreshBindingRun(clientId(), pending.thumbprint(),
                confirmationOf(accessToken), String.valueOf(issued.get("token_type")),
                refreshToken != null, attempts, Instant.now());
    }

    /** Carries the rotated refresh token from one attempt to the next. */
    private final class Refreshing {

        private String refreshToken;
        private String lastIssuedRefreshToken;

        private Refreshing(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        private RefreshBindingAttempt attempt(String label, String description, DpopKeyPair key) {
            RefreshBindingAttempt attempt = refresh(label, description, this.refreshToken, key,
                    issued -> this.lastIssuedRefreshToken = issued);
            if (attempt.isSuccess() && this.lastIssuedRefreshToken != null) {
                this.refreshToken = this.lastIssuedRefreshToken;
            }
            return attempt;
        }
    }

    /**
     * One refresh request. The client authenticates with nothing but its id, which is the whole
     * point: if the key does not decide who may use this token, nothing does.
     */
    @SuppressWarnings("unchecked")
    private RefreshBindingAttempt refresh(String label, String description, String refreshToken,
                                          DpopKeyPair key) {
        return refresh(label, description, refreshToken, key, issued -> {
        });
    }

    @SuppressWarnings("unchecked")
    private RefreshBindingAttempt refresh(String label, String description, String refreshToken,
                                          DpopKeyPair key, java.util.function.Consumer<String> rotated) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        form.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());

        return restClient.post()
                .uri("/oauth2/token")
                .headers(headers -> {
                    if (key != null) {
                        headers.add(DPOP_HEADER, key.proof("POST", tokenEndpoint(), null));
                    }
                })
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    Map<String, Object> body = response.bodyTo(Map.class);
                    if (status != 200 || body == null || body.get("access_token") == null) {
                        return new RefreshBindingAttempt(label, description, status, null, null,
                                refusalOf(body));
                    }
                    if (body.get(OAuth2ParameterNames.REFRESH_TOKEN) != null) {
                        rotated.accept(String.valueOf(body.get(OAuth2ParameterNames.REFRESH_TOKEN)));
                    }
                    String accessToken = String.valueOf(body.get("access_token"));
                    String confirmation = confirmationOf(accessToken);
                    return new RefreshBindingAttempt(label, description, status,
                            String.valueOf(body.get("token_type")), confirmation,
                            confirmation == null
                                    ? "A new access token, tied to nothing."
                                    : "A new access token, still tied to the same key.");
                }, false);
    }

    /** What the server said, with the error code when it offered no description. */
    private static String refusalOf(Map<String, Object> body) {
        if (body == null) {
            return "Refused.";
        }
        Object description = body.get("error_description");
        return description != null
                ? String.valueOf(description)
                : "Refused: " + body.get("error");
    }

    /** RFC 9449 section 6.1: the thumbprint the token is bound to, when it is bound to anything. */
    @SuppressWarnings("unchecked")
    private static String confirmationOf(String accessToken) {
        try {
            Object cnf = JWTParser.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
            return cnf instanceof Map<?, ?> map ? String.valueOf(((Map<String, Object>) map).get("jkt")) : null;
        } catch (Exception ex) {
            return null;
        }
    }
}

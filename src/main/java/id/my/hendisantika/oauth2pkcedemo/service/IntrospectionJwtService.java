package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionJwtResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionJwtRun;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionResponseAttempt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 08.15
 */
@Slf4j
@Service
public class IntrospectionJwtService {

    private final RestClient restClient;
    private final DemoProperties properties;

    /**
     * A decoder of this demo's own, because the server's will not take its own answer: the
     * {@code JwtDecoder} bean is the one the authorization server uses for access tokens, and it
     * refuses any {@code typ} but a JWT or {@code at+jwt}. That refusal is the {@code typ} header
     * doing exactly what RFC 9701 gives it for - an introspection response must not be mistakeable
     * for an access token - so the right answer is a second decoder, not a laxer first one.
     */
    private final JwtDecoder introspectionDecoder;

    public IntrospectionJwtService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(properties.issuerUri() + "/oauth2/jwks")
                .build();
        // The type is checked, just not against the default list: Spring Security's own validator
        // chain insists on typ JWT, which is why the server's decoder refuses this response.
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtTypeValidator(IntrospectionJwtResponseHandler.JWT_TYPE)));
        this.introspectionDecoder = decoder;
    }

    public String introspectingClientId() {
        return properties.exchangeClient().clientId();
    }

    public String otherClientId() {
        return properties.relayClient().clientId();
    }

    public String introspectionEndpoint() {
        return properties.issuerUri() + "/oauth2/introspect";
    }

    /**
     * Mints one access token and asks about it four ways: as plain JSON, as a signed JWT, as a
     * signed JWT for a different caller, and - still signed - about a token that was never issued.
     */
    public IntrospectionJwtRun run() {
        String accessToken = clientCredentialsToken(properties.exchangeClient());
        List<IntrospectionResponseAttempt> attempts = new ArrayList<>();

        attempts.add(introspect("Asking for JSON, as everyone always has",
                "application/json", accessToken, properties.exchangeClient()));
        attempts.add(introspect("Asking for a signed response",
                IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE, accessToken, properties.exchangeClient()));
        attempts.add(introspect("The same token, asked about by somebody else",
                IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE, accessToken, properties.relayClient()));
        attempts.add(introspect("A token that was never issued",
                IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE, "a-token-nobody-minted",
                properties.exchangeClient()));

        log.debug("Introspection JWT run finished with {} attempts", attempts.size());
        return new IntrospectionJwtRun(introspectingClientId(), otherClientId(),
                List.copyOf(attempts), Instant.now());
    }

    /** One introspection request, and whatever form the answer took. */
    private IntrospectionResponseAttempt introspect(String label, String accept, String token,
                                                    DemoProperties.Client caller) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);

        return restClient.post()
                .uri("/oauth2/introspect")
                .header(HttpHeaders.AUTHORIZATION, basicAuth(caller))
                .header(HttpHeaders.ACCEPT, accept)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    String contentType = response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
                    String body = response.bodyTo(String.class);
                    boolean signed = contentType != null
                            && contentType.contains(IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);
                    return signed
                            ? fromJwt(label, accept, contentType, body)
                            : fromJson(label, accept, contentType, body);
                }, false);
    }

    /**
     * Decoding verifies the signature against the keys the server publishes, which is the whole
     * difference: a resource server can keep this answer and still prove where it came from.
     */
    private IntrospectionResponseAttempt fromJwt(String label, String accept, String contentType,
                                                 String body) {
        try {
            Jwt jwt = introspectionDecoder.decode(body);
            return new IntrospectionResponseAttempt(label, accept, contentType, true,
                    String.valueOf(jwt.getHeaders().get("typ")),
                    String.valueOf(jwt.getClaimAsString("iss")),
                    String.join(", ", jwt.getAudience()), true,
                    new TreeMap<>(IntrospectionJwtResponseHandler.introspectionOf(jwt)), body);
        } catch (Exception ex) {
            log.debug("The signed introspection response did not verify: {}", ex.getMessage());
            return new IntrospectionResponseAttempt(label, accept, contentType, true, null, null,
                    null, false, Map.of(), body);
        }
    }

    /** The RFC 7662 form: true of nothing in particular, addressed to nobody, signed by no one. */
    @SuppressWarnings("unchecked")
    private IntrospectionResponseAttempt fromJson(String label, String accept, String contentType,
                                                  String body) {
        Map<String, Object> claims;
        try {
            claims = new TreeMap<>((Map<String, Object>) new tools.jackson.databind.ObjectMapper()
                    .readValue(body == null ? "{}" : body, Map.class));
        } catch (Exception ex) {
            claims = Map.of();
        }
        return new IntrospectionResponseAttempt(label, accept, contentType, false, null, null, null,
                null, claims, body);
    }

    /** A token of its own to ask about, which the exchange client can mint without a user. */
    @SuppressWarnings("unchecked")
    private String clientCredentialsToken(DemoProperties.Client client) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "api.read");
        Map<String, Object> body = restClient.post()
                .uri("/oauth2/token")
                .header(HttpHeaders.AUTHORIZATION, basicAuth(client))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        if (body == null || body.get("access_token") == null) {
            throw new IllegalStateException("No token to introspect");
        }
        return String.valueOf(body.get("access_token"));
    }

    private static String basicAuth(DemoProperties.Client client) {
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.AuthorizationCodeBindingController;
import id.my.hendisantika.oauth2pkcedemo.security.CodeBindingAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.CodeBindingRun;
import id.my.hendisantika.oauth2pkcedemo.security.DpopBoundAuthorizationCodeFilter;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import id.my.hendisantika.oauth2pkcedemo.security.PendingCodeBinding;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
@Slf4j
@Service
public class AuthorizationCodeBindingService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RestClient restClient;
    private final DemoProperties properties;

    public AuthorizationCodeBindingService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * RFC 9449 section 10 is explicit that the protection only holds when a unique key is used per
     * authorization request, so a run generates its own rather than reusing one.
     */
    public PendingCodeBinding start(boolean bound) {
        String codeVerifier = randomUrlSafe(64);
        return new PendingCodeBinding(bound,
                bound ? DpopKeyPair.generate() : null,
                codeVerifier,
                codeChallenge(codeVerifier),
                randomUrlSafe(16));
    }

    /** The parameters this client sends to the authorization endpoint, bound run or not. */
    public Map<String, String> authorizationParameters(PendingCodeBinding pending) {
        DemoProperties.Client client = properties.codeBindingClient();
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.STATE, pending.state());
        parameters.put("code_challenge", pending.codeChallenge());
        parameters.put("code_challenge_method", "S256");
        if (pending.bound()) {
            parameters.put(DpopBoundAuthorizationCodeFilter.DPOP_JKT, pending.thumbprint());
        }
        return parameters;
    }

    public String authorizationUri(PendingCodeBinding pending) {
        UriComponentsBuilder builder =
                UriComponentsBuilder.fromUriString(properties.issuerUri() + "/oauth2/authorize");
        authorizationParameters(pending).forEach(builder::queryParam);
        return builder.build().encode().toUriString();
    }

    /**
     * Redeems one authorization code several ways over. Every attempt sends the correct
     * {@code code_verifier}: the attacker being modelled has the code <em>and</em> the PKCE secret,
     * which is the only situation in which binding the code to a key adds anything.
     * <p>
     * The failing attempts come first on purpose. A rejected token request leaves the code
     * outstanding, so the same code can then be redeemed properly - and the replay that follows
     * shows what happens once it has been.
     */
    public CodeBindingRun redeem(PendingCodeBinding pending, String code) {
        List<CodeBindingAttempt> attempts = new ArrayList<>();
        String tokenEndpoint = properties.issuerUri() + "/oauth2/token";

        if (pending.bound()) {
            DpopKeyPair attackerKey = DpopKeyPair.generate();
            attempts.add(attempt("The code and the verifier alone",
                    "Everything a stolen authorization code gets you, presented with no proof.",
                    pending, code, null, null));
            attempts.add(attempt("A proof from another key",
                    "A well-formed DPoP proof, signed by a key the code was never bound to.",
                    pending, code, attackerKey, attackerKey.proof("POST", tokenEndpoint, null)));
            attempts.add(attempt("A proof from the bound key",
                    "The client that asked for the code, holding the private key it named.",
                    pending, code, pending.key(), pending.key().proof("POST", tokenEndpoint, null)));
            attempts.add(attempt("The same code again",
                    "The rightful client replaying the code it has already redeemed.",
                    pending, code, pending.key(), pending.key().proof("POST", tokenEndpoint, null)));
        } else {
            attempts.add(attempt("The code and the verifier alone",
                    "No key was named in the authorization request, so there is nothing to prove.",
                    pending, code, null, null));
            attempts.add(attempt("The same code again",
                    "Single use is enforced whether or not the code was bound to a key.",
                    pending, code, null, null));
        }

        log.debug("Redeemed a {} authorization code {} ways",
                pending.bound() ? "bound" : "unbound", attempts.size());
        return new CodeBindingRun(pending.bound(), pending.thumbprint(),
                pending.bound() ? pending.key().publicJwkJson() : null,
                authorizationParameters(pending), code, attempts, Instant.now());
    }

    /**
     * One token request, reported as the server answered it. A failure is as much a result as a
     * success here, so the error body is kept rather than thrown.
     */
    @SuppressWarnings("unchecked")
    private CodeBindingAttempt attempt(String label, String description, PendingCodeBinding pending,
                                       String code, DpopKeyPair key, String proof) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        form.add(OAuth2ParameterNames.CODE, code);
        form.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri());
        form.add(OAuth2ParameterNames.CLIENT_ID, properties.codeBindingClient().clientId());
        form.add("code_verifier", pending.codeVerifier());

        return restClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(headers -> {
                    if (proof != null) {
                        headers.add("DPoP", proof);
                    }
                })
                .body(form)
                .exchange((request, response) -> {
                    Map<String, Object> body = response.bodyTo(Map.class);
                    int status = response.getStatusCode().value();
                    String thumbprint = key == null ? null : key.thumbprint();
                    if (status != 200 || body == null) {
                        return new CodeBindingAttempt(label, description, thumbprint, status,
                                errorOf(body), null, null);
                    }
                    String accessToken = String.valueOf(body.get("access_token"));
                    return new CodeBindingAttempt(label, description, thumbprint, status,
                            "An access token was issued",
                            String.valueOf(body.get(OAuth2ParameterNames.TOKEN_TYPE)),
                            confirmationThumbprint(accessToken));
                }, false);
    }

    private static String errorOf(Map<String, Object> body) {
        if (body == null) {
            return "The request was rejected";
        }
        Object description = body.get("error_description");
        return description == null ? String.valueOf(body.get("error")) : String.valueOf(description);
    }

    /**
     * RFC 9449 section 6.1: the key the issued token is itself bound to. For a run that asked for
     * {@code dpop_jkt}, this coming back equal to it is the end-to-end binding the section promises.
     */
    @SuppressWarnings("unchecked")
    private static String confirmationThumbprint(String accessToken) {
        try {
            Object cnf = JWTParser.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
            return cnf instanceof Map<?, ?> map ? String.valueOf(((Map<String, Object>) map).get("jkt")) : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private String redirectUri() {
        return properties.issuerUri() + AuthorizationCodeBindingController.CALLBACK_URI;
    }

    private static String codeChallenge(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute the code challenge", ex);
        }
    }

    private static String randomUrlSafe(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}

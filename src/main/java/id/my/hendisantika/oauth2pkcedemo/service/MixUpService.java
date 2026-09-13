package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.MixUpController;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.MixUpRun;
import id.my.hendisantika.oauth2pkcedemo.security.MixUpStep;
import id.my.hendisantika.oauth2pkcedemo.security.PendingMixUp;
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
 * Time: 18.33
 */
@Slf4j
@Service
public class MixUpService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RestClient restClient;
    private final MixUpAttackerService attacker;
    private final DemoProperties properties;

    public MixUpService(MixUpAttackerService attacker, DemoProperties properties) {
        this.attacker = attacker;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * The client is about to start a login at the authorization server the user picked - the
     * attacker's. Nothing is wrong yet: choosing a provider that turns out to be hostile is a
     * situation any client supporting more than one has to survive.
     */
    public PendingMixUp start(boolean checkIssuer) {
        String codeVerifier = randomUrlSafe(64);
        return new PendingMixUp(randomUrlSafe(16), codeVerifier, codeChallenge(codeVerifier),
                attacker.issuer(), checkIssuer);
    }

    public Map<String, String> authorizationParameters(PendingMixUp pending) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, "client-id-at-the-attacker");
        parameters.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri());
        parameters.put(OAuth2ParameterNames.SCOPE, "openid profile");
        parameters.put(OAuth2ParameterNames.STATE, pending.state());
        parameters.put("code_challenge", pending.codeChallenge());
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    public String authorizationUri(PendingMixUp pending) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(attacker.authorizationEndpoint());
        authorizationParameters(pending).forEach(builder::queryParam);
        return builder.build().encode().toUriString();
    }

    /**
     * The moment the attack turns on. A code has arrived at the client's redirect URI, and the
     * client has to decide which authorization server it belongs to. Its own record says the
     * attacker's; the response itself says otherwise, but only a client that reads {@code iss} will
     * ever notice the difference.
     */
    public MixUpRun redeem(PendingMixUp pending, String code, String receivedIssuer) {
        List<MixUpStep> steps = new ArrayList<>();
        steps.add(MixUpStep.of("Client",
                "Started a login at the authorization server the user picked",
                attacker.authorizationEndpoint()));
        steps.add(MixUpStep.harmful("Attacker's server",
                "Did not authenticate anyone. Forwarded the request to the honest server, "
                        + "keeping the client's state, redirect URI and code challenge",
                properties.issuerUri() + "/oauth2/authorize"));
        steps.add(MixUpStep.of("Honest server",
                "Signed the user in and issued an authorization code to the client's redirect URI",
                redirectUri()));
        steps.add(MixUpStep.of("Honest server",
                "Identified itself in the response, as RFC 9207 requires",
                IssuerIdentifierResponseHandler.ISS + "=" + receivedIssuer));

        if (pending.checkIssuer()) {
            return detected(pending, receivedIssuer, steps);
        }
        return stolen(pending, code, receivedIssuer, steps);
    }

    /** What the parameter is for: one comparison, made before anything is sent anywhere. */
    private MixUpRun detected(PendingMixUp pending, String receivedIssuer, List<MixUpStep> steps) {
        steps.add(MixUpStep.of("Client",
                "Compared the issuer that answered with the one it started with - they differ",
                "expected " + pending.expectedIssuer() + ", got " + receivedIssuer));
        steps.add(MixUpStep.of("Client",
                "Abandoned the response. The code was never sent anywhere",
                "No token request was made"));
        log.debug("Mix-up detected: expected {}, got {}", pending.expectedIssuer(), receivedIssuer);
        return new MixUpRun(true, pending.expectedIssuer(), receivedIssuer, steps,
                "The mismatch was caught and the flow abandoned.", false, null, Instant.now());
    }

    /**
     * What happens without it. The client posts the code to the token endpoint of the server it
     * believes answered - and posts the code verifier with it, because that is what a token request
     * carries. PKCE is not bypassed here; it is handed over.
     */
    private MixUpRun stolen(PendingMixUp pending, String code, String receivedIssuer,
                            List<MixUpStep> steps) {
        steps.add(MixUpStep.of("Client",
                "Did not look at who answered. Its own note said the attacker's server, so that is "
                        + "where the token request went",
                attacker.tokenEndpoint()));

        Map<String, Object> report = postTokenRequest(code, pending.codeVerifier());
        boolean redeemed = Boolean.TRUE.equals(report.get("redeemed"));
        String subject = report.get("subject") == null ? null : String.valueOf(report.get("subject"));

        steps.add(MixUpStep.harmful("Attacker's server",
                "Received the authorization code and the PKCE code verifier together",
                "code_verifier=" + pending.codeVerifier()));
        steps.add(redeemed
                ? MixUpStep.harmful("Attacker's server",
                        "Redeemed them at the honest server and holds an access token for the user",
                        "sub=" + subject)
                : MixUpStep.of("Attacker's server",
                        "Tried to redeem them at the honest server and failed",
                        "No token issued"));

        log.warn("Mix-up succeeded: the authorization code left for {}", attacker.tokenEndpoint());
        return new MixUpRun(false, pending.expectedIssuer(), receivedIssuer, steps,
                redeemed
                        ? "The code was handed to the attacker, who redeemed it."
                        : "The code was handed to the attacker.",
                true, subject, Instant.now());
    }

    /** An ordinary token request, sent to the wrong place. Nothing about it is malformed. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> postTokenRequest(String code, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        form.add(OAuth2ParameterNames.CODE, code);
        form.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri());
        form.add(OAuth2ParameterNames.CLIENT_ID, "client-id-at-the-attacker");
        form.add("code_verifier", codeVerifier);

        return restClient.post()
                .uri("/mixup/attacker/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
    }

    private String redirectUri() {
        return properties.issuerUri() + MixUpController.CALLBACK_URI;
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

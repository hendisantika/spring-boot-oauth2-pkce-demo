package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DpopDemoResult;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
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
 * Time: 14.24
 */
@Slf4j
@Service
public class DpopService {

    private static final String DPOP_HEADER = "DPoP";

    /** This client's key. In a browser app it would live in non-extractable IndexedDB storage. */
    private final DpopKeyPair clientKey = DpopKeyPair.generate();

    /** A second key standing in for whoever stole the token. */
    private final DpopKeyPair attackerKey = DpopKeyPair.generate();

    private final RestClient restClient;
    private final DemoProperties properties;

    public DpopService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /**
     * Trades a refresh token for a DPoP-bound access token, then tries the protected resource three
     * ways: correctly, without a proof at all, and with a proof signed by a different key.
     */
    @SuppressWarnings("unchecked")
    public DpopDemoResult run(String refreshToken) {
        String tokenEndpoint = properties.issuerUri() + "/oauth2/token";
        String proofForToken = clientKey.proof("POST", tokenEndpoint, null);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);

        Map<String, Object> tokenResponse = restClient.post()
                .uri("/oauth2/token")
                .header("Authorization", basicAuthHeader())
                .header(DPOP_HEADER, proofForToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        String accessToken = (String) tokenResponse.get("access_token");
        String tokenType = (String) tokenResponse.get("token_type");
        log.debug("Obtained a {} token bound to {}", tokenType, clientKey.thumbprint());

        String apiUri = properties.issuerUri() + "/api/me";
        List<DpopDemoResult.ApiCall> calls = new ArrayList<>();
        calls.add(call("With a matching proof",
                "Authorization: DPoP <token> plus a proof signed by the bound key.",
                accessToken, clientKey.proof("GET", apiUri, accessToken)));
        calls.add(call("With no proof",
                "The token alone, as a stolen one would be presented.",
                accessToken, null));
        calls.add(call("With someone else's proof",
                "A syntactically valid proof, signed by a key the token is not bound to.",
                accessToken, attackerKey.proof("GET", apiUri, accessToken)));

        return new DpopDemoResult(
                clientKey.thumbprint(),
                clientKey.publicJwkJson(),
                tokenType,
                accessToken,
                claimsOf(accessToken),
                proofForToken,
                claimsOf(proofForToken),
                calls);
    }

    private DpopDemoResult.ApiCall call(String label, String description, String accessToken, String proof) {
        return restClient.get()
                .uri("/api/me")
                .header("Authorization", DPOP_HEADER + " " + accessToken)
                .headers(headers -> {
                    if (proof != null) {
                        headers.add(DPOP_HEADER, proof);
                    }
                })
                .exchange((request, response) -> {
                    String body = response.bodyTo(String.class);
                    return new DpopDemoResult.ApiCall(label, description,
                            response.getStatusCode().value(),
                            body == null || body.isBlank() ? "(empty)" : body);
                }, false);
    }

    private static Map<String, Object> claimsOf(String jwt) {
        try {
            return new TreeMap<>(JWTParser.parse(jwt).getJWTClaimsSet().getClaims());
        } catch (ParseException ex) {
            return Map.of("error", "Unable to parse: " + ex.getMessage());
        }
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.confidentialClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

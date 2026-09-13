package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.15
 */
@Controller
@RequiredArgsConstructor
public class JarController {

    /** A fixed verifier keeps the demo's links stable; a real client makes a fresh one each time. */
    private static final String CODE_VERIFIER =
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-vErsWXBGJiGMvZmJXzxg";

    private final JarRequestSigner jarRequestSigner;
    private final DemoProperties properties;

    @GetMapping("/jar")
    public String jarPage(Model model) {
        DemoProperties.Client client = properties.client();
        Map<String, String> parameters = authorizationParameters(client);
        String requestObject = jarRequestSigner.sign(client.clientId(), properties.issuerUri(), parameters);

        model.addAttribute("clientId", client.clientId());
        model.addAttribute("parameters", parameters);
        model.addAttribute("requestObject", requestObject);
        model.addAttribute("requestObjectClaims", claimsOf(requestObject));
        model.addAttribute("jwkSetUri", JarJwkSetController.JAR_JWK_SET_URI);

        String base = properties.issuerUri() + "/oauth2/authorize";
        model.addAttribute("signedUri", authorizeUri(base, client.clientId(), requestObject, null));
        // The same object with a scope bolted onto the URL. RFC 9101 says the server reads the
        // object and nothing else, so this changes nothing - which is the point.
        model.addAttribute("tamperedUri",
                authorizeUri(base, client.clientId(), requestObject, "admin.everything"));
        model.addAttribute("brokenUri",
                authorizeUri(base, client.clientId(), corrupt(requestObject), null));
        model.addAttribute("foreignUri", authorizeUri(base, client.clientId(),
                jarRequestSigner.signWithAnotherKey(client.clientId(), properties.issuerUri(), parameters),
                null));
        return "jar";
    }

    private Map<String, String> authorizationParameters(DemoProperties.Client client) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + client.registrationId());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.STATE, "jar-demo-state");
        parameters.put("code_challenge", codeChallenge());
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    private static String authorizeUri(String base, String clientId, String requestObject, String extraScope) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(base)
                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                .queryParam(JwtSecuredAuthorizationRequestFilter.REQUEST, requestObject);
        if (extraScope != null) {
            builder.queryParam(OAuth2ParameterNames.SCOPE, extraScope);
        }
        return builder.build().toUriString();
    }

    /** Flips one character of the signature, which is all it takes. */
    private static String corrupt(String requestObject) {
        int lastDot = requestObject.lastIndexOf('.');
        char victim = requestObject.charAt(lastDot + 1);
        return requestObject.substring(0, lastDot + 1)
                + (victim == 'A' ? 'B' : 'A')
                + requestObject.substring(lastDot + 2);
    }

    private static Map<String, Object> claimsOf(String jwt) {
        try {
            return new TreeMap<>(JWTParser.parse(jwt).getJWTClaimsSet().getClaims());
        } catch (Exception ex) {
            return Map.of("error", String.valueOf(ex.getMessage()));
        }
    }

    private static String codeChallenge() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(CODE_VERIFIER.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}

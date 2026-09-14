package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 21.30
 */
@RestController
@RequiredArgsConstructor
public class HostedRequestObjectController {

    /** Where the client hosting its own request object would put it. RFC 9101 section 5.2.1. */
    public static final String HOSTED_URI = "/hosted/request-object.jwt";

    /** The same object, served as something else, for RFC 9101 section 10.4.1 clause (b). */
    public static final String WRONG_TYPE_URI = "/hosted/wrong-type.jwt";

    /** An object that points at another one, which section 4 says may not happen. */
    public static final String RECURSIVE_URI = "/hosted/recursive.jwt";

    /** Registered by a different client, so that one client cannot reach it. */
    public static final String OTHER_CLIENT_URI = "/hosted/other-client.jwt";

    /**
     * For a client that did not exist when this application started. A client hosting its own
     * request object knows its own client id; this stands in for that by being told.
     */
    public static final String FOR_CLIENT_URI = "/hosted/for-client.jwt";

    /** The media type RFC 9101 section 10.8 gives a request object. */
    public static final String MEDIA_TYPE = "application/oauth-authz-req+jwt";

    /** A fixed challenge; this demo is about the reference, not about PKCE. */
    public static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private final DemoProperties properties;
    private final JarRequestSigner signer;

    @GetMapping(value = HOSTED_URI, produces = MEDIA_TYPE)
    public ResponseEntity<String> requestObject() {
        return served(signed(properties.fetchedRequestClient(), Map.of()));
    }

    @GetMapping(value = WRONG_TYPE_URI, produces = "text/plain")
    public ResponseEntity<String> wrongType() {
        return ResponseEntity.ok()
                .header("Content-Type", "text/plain")
                .body(signed(properties.fetchedRequestClient(), Map.of()));
    }

    @GetMapping(value = RECURSIVE_URI, produces = MEDIA_TYPE)
    public ResponseEntity<String> recursive() {
        return served(signed(properties.fetchedRequestClient(),
                Map.of(OAuth2ParameterNames.REQUEST_URI, properties.issuerUri() + HOSTED_URI)));
    }

    @GetMapping(value = OTHER_CLIENT_URI, produces = MEDIA_TYPE)
    public ResponseEntity<String> otherClient() {
        return served(signed(properties.confidentialClient(), Map.of()));
    }

    /**
     * @param clientId whose request object this is. The redirect URI is the one a dynamically
     *                 registered client gets, since that is who asks for this.
     */
    @GetMapping(value = FOR_CLIENT_URI, produces = MEDIA_TYPE)
    public ResponseEntity<String> forClient(@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/adhoc");
        parameters.put(OAuth2ParameterNames.STATE, "hosted-for-client");
        parameters.put("code_challenge", CODE_CHALLENGE);
        parameters.put("code_challenge_method", "S256");
        return served(signer.sign(clientId, properties.issuerUri(), parameters));
    }

    private static ResponseEntity<String> served(String requestObject) {
        return ResponseEntity.ok().header("Content-Type", MEDIA_TYPE).body(requestObject);
    }

    private String signed(DemoProperties.Client client, Map<String, String> extra) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + client.registrationId());
        parameters.put(OAuth2ParameterNames.STATE, "hosted-request-object");
        parameters.put("code_challenge", CODE_CHALLENGE);
        parameters.put("code_challenge_method", "S256");
        parameters.putAll(extra);
        return signer.sign(client.clientId(), properties.issuerUri(), parameters);
    }
}

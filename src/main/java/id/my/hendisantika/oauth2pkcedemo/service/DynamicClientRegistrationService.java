package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.RegistrationAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RegistrationRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
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
 * Time: 19.14
 */
@Slf4j
@Service
public class DynamicClientRegistrationService {

    /** The scope an initial access token needs, and the only one it may carry. */
    public static final String CREATE_SCOPE = "client.create";

    /** What the registration access token handed back afterwards is good for. */
    public static final String READ_SCOPE = "client.read";

    private final RestClient restClient;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationServerSettings settings;
    private final DemoProperties properties;

    public DynamicClientRegistrationService(RegisteredClientRepository registeredClientRepository,
                                            AuthorizationServerSettings settings,
                                            DemoProperties properties) {
        this.registeredClientRepository = registeredClientRepository;
        this.settings = settings;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public String registrationEndpoint() {
        return properties.issuerUri() + settings.getOidcClientRegistrationEndpoint();
    }

    /**
     * The client metadata a caller sends. RFC 7591 section 2 defines a good deal more than this;
     * these are the fields that matter for a client that will run the authorization code flow.
     */
    public Map<String, Object> clientMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("client_name", "Ad hoc client");
        metadata.put("redirect_uris",
                List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"));
        metadata.put("grant_types", List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
        metadata.put("response_types", List.of("code"));
        return metadata;
    }

    /**
     * Registers one client and, around it, the requests that do not work - each of them a rule this
     * server enforces that is worth seeing enforced rather than described.
     */
    public RegistrationRun run() {
        List<RegistrationAttempt> attempts = new ArrayList<>();
        Map<String, Object> metadata = clientMetadata();

        attempts.add(register("With no access token",
                "RFC 7591 section 3 leaves the endpoint's protection to the server. This one wants a "
                        + "token.", metadata, null).attempt());

        attempts.add(register("With a token carrying both scopes",
                "client.create and client.read together, from the same client credentials grant.",
                metadata, token(CREATE_SCOPE + " " + READ_SCOPE)).attempt());

        Map<String, Object> withScope = new LinkedHashMap<>(metadata);
        withScope.put(OAuth2ParameterNames.SCOPE, "openid profile");
        attempts.add(register("Asking for scopes",
                "RFC 7591 section 2 defines a scope field. This server refuses any request that "
                        + "sets it.", withScope, token(CREATE_SCOPE)).attempt());

        String initialAccessToken = token(CREATE_SCOPE);
        RegistrationResult registration = register("A well-formed registration",
                "One token, exactly one scope, and no request for authority.", metadata,
                initialAccessToken);
        attempts.add(registration.attempt());

        attempts.add(register("The same initial access token again",
                "It was spent by the registration above.", metadata, initialAccessToken).attempt());

        Map<String, Object> issued = registration.issued();
        attempts.add(read(issued));

        String clientId = issued.get(OAuth2ParameterNames.CLIENT_ID) == null
                ? null : String.valueOf(issued.get(OAuth2ParameterNames.CLIENT_ID));
        RegisteredClient stored = clientId == null ? null
                : registeredClientRepository.findByClientId(clientId);

        log.debug("Dynamic registration run finished, client_id={}", clientId);
        return new RegistrationRun(metadata, issued, clientId,
                issued.get("registration_client_uri") == null
                        ? null : String.valueOf(issued.get("registration_client_uri")),
                stored != null && stored.getClientSettings().isRequireProofKey(),
                stored != null && stored.getClientSettings().isRequireAuthorizationConsent(),
                stored == null ? List.of() : List.copyOf(stored.getScopes()),
                attempts, Instant.now());
    }

    /** One request and, when it worked, what the server handed back. */
    private record RegistrationResult(RegistrationAttempt attempt, Map<String, Object> issued) {
    }

    /** A client credentials token for exactly the scopes named, and nothing else. */
    @SuppressWarnings("unchecked")
    private String token(String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        form.add(OAuth2ParameterNames.SCOPE, scope);

        Map<String, Object> response = restClient.post()
                .uri("/oauth2/token")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        return response == null ? null : String.valueOf(response.get("access_token"));
    }

    @SuppressWarnings("unchecked")
    private RegistrationResult register(String label, String description,
                                        Map<String, Object> metadata, String accessToken) {
        return restClient.post()
                .uri(settings.getOidcClientRegistrationEndpoint())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> {
                    if (accessToken != null) {
                        headers.setBearerAuth(accessToken);
                    }
                })
                .body(metadata)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    Map<String, Object> body = readBody(response.bodyTo(Map.class));
                    if (status < 200 || status >= 300) {
                        return new RegistrationResult(
                                new RegistrationAttempt(label, description, status,
                                        errorOf(body, response.getHeaders().getFirst("WWW-Authenticate")),
                                        accessToken == null
                                                ? "no Authorization header"
                                                : "Bearer token sent"),
                                Map.of());
                    }
                    return new RegistrationResult(
                            new RegistrationAttempt(label, description, status,
                                    "A client was registered.",
                                    "client_id=" + body.get(OAuth2ParameterNames.CLIENT_ID)),
                            body);
                }, false);
    }

    /** RFC 7592: read the registration back, with the token the registration handed out. */
    @SuppressWarnings("unchecked")
    private RegistrationAttempt read(Map<String, Object> issued) {
        String label = "Reading the registration back";
        String description = "With the registration access token, at the registration client URI.";
        Object uri = issued.get("registration_client_uri");
        Object registrationAccessToken = issued.get("registration_access_token");
        if (uri == null || registrationAccessToken == null) {
            return new RegistrationAttempt(label, description, 0,
                    "There is no registration to read.", "-");
        }

        return restClient.get()
                .uri(String.valueOf(uri))
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(String.valueOf(registrationAccessToken)))
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    Map<String, Object> body = readBody(response.bodyTo(Map.class));
                    return new RegistrationAttempt(label, description, status,
                            status == 200 ? "The registration came back."
                                    : errorOf(body, response.getHeaders().getFirst("WWW-Authenticate")),
                            "that token carries one scope: " + READ_SCOPE);
                }, false);
    }

    private static Map<String, Object> readBody(Map<String, Object> body) {
        return body == null ? Map.of() : body;
    }

    /**
     * A refusal with no body still says something: Spring Security answers an unauthenticated call
     * with a challenge naming where to find out how to authenticate.
     */
    private static String errorOf(Map<String, Object> body, String challenge) {
        if (body.isEmpty()) {
            return challenge == null ? "The request was refused." : "WWW-Authenticate: " + challenge;
        }
        Object description = body.get("error_description");
        return description == null ? String.valueOf(body.get("error")) : String.valueOf(description);
    }

    private String basicAuthHeader() {
        DemoProperties.Client registrar = properties.registrarClient();
        String credentials = registrar.clientId() + ":" + registrar.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}

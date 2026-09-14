package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.ClientRequiredAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.ClientRequiredRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectClientRegistrationConverters;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 20.05
 */
@Slf4j
@Service
public class ClientRequiredRequestObjectService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RequestObjectPolicy policy;
    private final AuthorizationServerSettings settings;
    private final RestClient restClient;

    public ClientRequiredRequestObjectService(DemoProperties properties, JarRequestSigner signer,
                                              RequestObjectPolicy policy,
                                              AuthorizationServerSettings settings) {
        this.properties = properties;
        this.signer = signer;
        this.policy = policy;
        this.settings = settings;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** The control: a client with nothing registered about request objects. */
    public DemoProperties.Client unlockedClient() {
        return properties.client();
    }

    /** False throughout, so nothing on this page can be the server-wide switch. */
    public boolean serverRequiresSignedRequestObjects() {
        return this.policy.requireSignedRequestObject();
    }

    public String registrationEndpoint() {
        return properties.issuerUri() + settings.getOidcClientRegistrationEndpoint();
    }

    /**
     * Registers two clients through the registration endpoint - one that requires signed request
     * objects, one that requires them and registered {@code none} in the same breath - and then
     * sends the same requests to them and to a client that registered nothing.
     */
    public ClientRequiredRun run() {
        // An initial access token is spent by the registration it authorises, so each of these
        // needs one of its own.
        Map<String, Object> locked = register(token(), Map.of(
                RequestObjectClientRegistrationConverters.REQUIRE_SIGNED_REQUEST_OBJECT, true));
        Map<String, Object> contradictory = register(token(), Map.of(
                RequestObjectClientRegistrationConverters.REQUIRE_SIGNED_REQUEST_OBJECT, true,
                RequestObjectClientRegistrationConverters.REQUEST_OBJECT_SIGNING_ALG,
                JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE));

        String lockedId = String.valueOf(locked.get(OAuth2ParameterNames.CLIENT_ID));
        String contradictoryId = String.valueOf(contradictory.get(OAuth2ParameterNames.CLIENT_ID));
        String redirectUri = redirectUri();

        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<ClientRequiredAttempt> attempts = new ArrayList<>();
        attempts.add(probe.plain("An ordinary request, from a client that registered nothing",
                "The control. Every page here that is not about JAR sends this.",
                unlockedClient().clientId(), "nothing",
                properties.issuerUri() + "/login/oauth2/code/" + unlockedClient().registrationId(),
                String.join(" ", unlockedClient().scopes())));
        attempts.add(probe.plain("An ordinary request",
                "The same request, to the client that asked to be locked down.",
                lockedId, "require_signed_request_object", redirectUri, scope()));
        attempts.add(probe.signed("A signed request object",
                "What the registration asked the client to send, and it works.",
                lockedId, "require_signed_request_object", redirectUri, scope()));
        attempts.add(probe.unsigned("An unsigned request object",
                "Refused by the algorithm it did not register rather than by the defence.",
                lockedId, "require_signed_request_object", redirectUri, scope()));
        attempts.add(probe.unsigned("An unsigned request object",
                "Exactly what its algorithm registration promised, and the defence refuses it.",
                contradictoryId, "require_signed_request_object + none", redirectUri, scope()));
        attempts.add(probe.signed("A signed request object",
                "What the defence asked for, refused by the algorithm the same registration named.",
                contradictoryId, "require_signed_request_object + none", redirectUri, scope()));

        log.debug("Client-required run finished; {} of {} accepted",
                attempts.stream().filter(ClientRequiredAttempt::accepted).count(), attempts.size());
        return new ClientRequiredRun(lockedId, contradictoryId, locked,
                serverRequiresSignedRequestObjects(), List.copyOf(attempts), Instant.now());
    }

    /**
     * Nothing. This server refuses a registration request that asks for scopes - the initial access
     * token carries {@code client.create} and a registration may not ask for authority beyond it -
     * so an ad-hoc client has none to ask for later either.
     */
    private String scope() {
        return "";
    }

    private String redirectUri() {
        return properties.issuerUri() + "/login/oauth2/code/adhoc";
    }

    /** RFC 7591 section 3: this server wants an initial access token, and the registrar holds one. */
    private String token() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        form.add(OAuth2ParameterNames.SCOPE, DynamicClientRegistrationService.CREATE_SCOPE);

        Map<String, Object> response = restClient.post()
                .uri("/oauth2/token")
                .header(HttpHeaders.AUTHORIZATION, basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        if (response == null) {
            throw new IllegalStateException("No initial access token came back");
        }
        return String.valueOf(response.get("access_token"));
    }

    /** One public client, registered with whatever extra metadata this run is about. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> register(String accessToken, Map<String, Object> extra) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("client_name", "Locked-down client");
        metadata.put("redirect_uris", List.of(redirectUri()));
        metadata.put("grant_types", List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
        metadata.put("response_types", List.of("code"));
        metadata.put("token_endpoint_auth_method", "none");
        metadata.putAll(extra);

        Map<String, Object> response = restClient.post()
                .uri(settings.getOidcClientRegistrationEndpoint())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(accessToken))
                .body(metadata)
                .retrieve()
                .body(Map.class);
        if (response == null || response.get(OAuth2ParameterNames.CLIENT_ID) == null) {
            throw new IllegalStateException("The registration endpoint returned no client");
        }
        return (Map<String, Object>) (Map<?, ?>) new LinkedHashMap<>(response);
    }

    private String basicAuthHeader() {
        DemoProperties.Client registrar = properties.registrarClient();
        String credentials = registrar.clientId() + ":" + registrar.clientSecret();
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /** A browser with a session, sending one authorization request at a time. */
    private final class Probe {

        private final RestClient browser;
        private final String base = properties.issuerUri();

        private Probe() {
            HttpClient httpClient = HttpClient.newBuilder()
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            this.browser = RestClient.builder()
                    .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                    .build();
        }

        private void signIn(String username, String password) {
            String page = browser.get().uri(base + "/login").retrieve().body(String.class);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("username", username);
            form.add("password", password);
            form.add("_csrf", csrf(page));
            browser.post()
                    .uri(base + "/login")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.getStatusCode().value(), false);
        }

        private ClientRequiredAttempt plain(String label, String description, String clientId,
                                            String registered, String redirectUri, String scope) {
            UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize");
            parameters(clientId, redirectUri, scope).forEach(uri::queryParam);
            return get(label, description, clientId, registered, "No request object",
                    uri.build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private ClientRequiredAttempt signed(String label, String description, String clientId,
                                             String registered, String redirectUri, String scope) {
            return withRequestObject(label, description, clientId, registered,
                    "Signed request object",
                    signer.sign(clientId, properties.issuerUri(),
                            parameters(clientId, redirectUri, scope)));
        }

        private ClientRequiredAttempt unsigned(String label, String description, String clientId,
                                               String registered, String redirectUri, String scope) {
            return withRequestObject(label, description, clientId, registered,
                    "Unsigned request object",
                    signer.unsigned(clientId, properties.issuerUri(),
                            parameters(clientId, redirectUri, scope)));
        }

        private ClientRequiredAttempt withRequestObject(String label, String description,
                                                        String clientId, String registered,
                                                        String sent, String requestObject) {
            return get(label, description, clientId, registered, sent,
                    UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                            .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                            .queryParam("request", requestObject)
                            .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private ClientRequiredAttempt get(String label, String description, String clientId,
                                          String registered, String sent, String uri) {
            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new ClientRequiredAttempt(label, description, clientId, registered,
                                sent, actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    private Map<String, String> parameters(String clientId, String redirectUri, String scope) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        if (!scope.isBlank()) {
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
        }
        parameters.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        parameters.put(OAuth2ParameterNames.STATE, randomUrlSafe(16));
        parameters.put("code_challenge", codeChallenge(randomUrlSafe(32)));
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    /**
     * Whether the server acted on the request. Reaching the consent screen counts: a dynamically
     * registered client asks for consent, and that screen is built from what the request said.
     */
    private static boolean actedOn(String location) {
        return location != null && !location.contains("error=")
                && (location.contains("code=") || location.contains("/oauth2/consent"));
    }

    /** Where it ended up - and for a refusal, what the refusal said. */
    private static String outcomeOf(String location, String body) {
        if (location != null) {
            if (location.contains("code=")) {
                return "an authorization code";
            }
            if (location.contains("/oauth2/consent")) {
                return "the consent screen";
            }
            Matcher matcher = Pattern.compile("[?&]error=([^&]*)").matcher(location);
            return matcher.find() ? matcher.group(1) : "somewhere else entirely";
        }
        if (body != null) {
            Matcher described = Pattern.compile("\"error_description\"\\s*:\\s*\"([^\"]+)\"")
                    .matcher(body);
            if (described.find()) {
                return described.group(1);
            }
            Matcher matcher = Pattern.compile("\\[([a-z_]+)]").matcher(body);
            return matcher.find() ? matcher.group(1) : "refused";
        }
        return "refused";
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page == null ? "" : page);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static String randomUrlSafe(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}

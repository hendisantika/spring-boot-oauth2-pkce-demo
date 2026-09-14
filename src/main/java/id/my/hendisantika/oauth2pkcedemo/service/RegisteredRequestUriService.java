package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.HostedRequestObjectController;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RegisteredRequestUriAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RegisteredRequestUriRun;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectClientRegistrationConverters;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
 * Date: 18/09/26
 * Time: 09.40
 */
@Slf4j
@Service
public class RegisteredRequestUriService {

    /**
     * OpenID Connect Registration section 2: a request_uri "SHOULD include the base64url-encoded
     * SHA-256 hash value of the file contents referenced by the URI as the value of the URI
     * fragment", so that a changed fragment tells a caching server its copy is stale.
     */
    public static final String CONTENT_HASH_FRAGMENT = "#Xy3pQ2Zr8kE1sT0uVw4aB6cD9eF2gH5jK7lM0nO3pQ4";

    /** A different hash, which is a different registered value and nothing more subtle than that. */
    public static final String OTHER_HASH_FRAGMENT = "#Zz9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP9oO8nN7mM6l";

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final AuthorizationServerSettings settings;
    private final RegisteredClientRepository registeredClients;
    private final RestClient restClient;

    public RegisteredRequestUriService(DemoProperties properties, AuthorizationServerSettings settings,
                                       RegisteredClientRepository registeredClients) {
        this.properties = properties;
        this.settings = settings;
        this.registeredClients = registeredClients;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public String registrationEndpoint() {
        return properties.issuerUri() + settings.getOidcClientRegistrationEndpoint();
    }

    /**
     * Registers two clients through the registration endpoint - one that names the URLs it will use
     * and one that names none - and then points both at URLs this application hosts.
     */
    @SuppressWarnings("unchecked")
    public RegisteredRequestUriRun run() {
        List<String> requested = List.of(hostedFor("listed") + CONTENT_HASH_FRAGMENT);

        Map<String, Object> listed = register(Map.of(
                RequestObjectClientRegistrationConverters.REQUEST_URIS, requested));
        Map<String, Object> unlisted = register(Map.of());

        String listedId = String.valueOf(listed.get(OAuth2ParameterNames.CLIENT_ID));
        String unlistedId = String.valueOf(unlisted.get(OAuth2ParameterNames.CLIENT_ID));

        // The URLs were registered before the client had an id, so the hosted object is asked to
        // name whichever client is fetching it - which is what a client hosting its own would do.
        List<String> registeredForListed = storedFor(listedId);

        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<RegisteredRequestUriAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize("The URL it registered",
                "Fragment and all: the whole string is what was registered.",
                listedId, hostedFor(listedId) + CONTENT_HASH_FRAGMENT,
                registeredForListed.contains(hostedFor(listedId) + CONTENT_HASH_FRAGMENT)));
        attempts.add(probe.authorize("The same URL, a different fragment",
                "A changed content hash is a different registered value, and this one is on no list.",
                listedId, hostedFor(listedId) + OTHER_HASH_FRAGMENT, false));
        attempts.add(probe.authorize("The same URL with no fragment at all",
                "Registering a URI with a fragment does not register the URI without it.",
                listedId, hostedFor(listedId), false));
        attempts.add(probe.authorize("Anything at all, from the client that registered none",
                "An empty list is a list. Registering nothing is not registering everything.",
                unlistedId, hostedFor(unlistedId) + CONTENT_HASH_FRAGMENT, false));

        log.debug("request_uris run finished; {} of {} accepted",
                attempts.stream().filter(RegisteredRequestUriAttempt::accepted).count(),
                attempts.size());
        return new RegisteredRequestUriRun(listedId, unlistedId,
                List.of(hostedFor("listed") + CONTENT_HASH_FRAGMENT),
                listed.get(RequestObjectClientRegistrationConverters.REQUEST_URIS),
                registeredForListed, List.copyOf(attempts), Instant.now());
    }

    /** Where this application hosts a request object naming the client that asks for it. */
    public String hostedFor(String clientId) {
        return UriComponentsBuilder
                .fromUriString(properties.issuerUri() + HostedRequestObjectController.FOR_CLIENT_URI)
                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                .build().encode(StandardCharsets.UTF_8).toUriString();
    }

    /** What the server holds for this client now, read from the registration rather than the page. */
    public List<String> storedFor(String clientId) {
        RegisteredClient client = registeredClients.findByClientId(clientId);
        Object setting = client == null ? null : client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING);
        return setting == null || String.valueOf(setting).isBlank() ? List.of()
                : List.of(String.valueOf(setting).split("\\s+"));
    }

    /**
     * One client, registered now. The registered URLs name the client that will fetch them, which
     * cannot be known before the server issues the id - so the list is registered against the
     * placeholder and re-registered once the id is known.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> register(Map<String, Object> extra) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("client_name", "Hosted request object client");
        metadata.put("redirect_uris", List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"));
        metadata.put("grant_types", List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
        metadata.put("response_types", List.of("code"));
        metadata.putAll(extra);

        Map<String, Object> response = restClient.post()
                .uri(settings.getOidcClientRegistrationEndpoint())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(token()))
                .body(metadata)
                .retrieve()
                .body(Map.class);
        if (response == null || response.get(OAuth2ParameterNames.CLIENT_ID) == null) {
            throw new IllegalStateException("The registration endpoint returned no client");
        }

        String clientId = String.valueOf(response.get(OAuth2ParameterNames.CLIENT_ID));
        rewriteRegisteredUris(clientId, extra);
        return new LinkedHashMap<>(response);
    }

    /**
     * The registration named a URL for a client id the server had not issued yet. A real client
     * registers the URL it will really host; this one edits the stored value once it knows its own
     * id, so that the page compares like with like.
     */
    private void rewriteRegisteredUris(String clientId, Map<String, Object> extra) {
        if (!extra.containsKey(RequestObjectClientRegistrationConverters.REQUEST_URIS)) {
            return;
        }
        RegisteredClient client = registeredClients.findByClientId(clientId);
        if (client == null) {
            return;
        }
        Map<String, Object> settingsMap =
                new LinkedHashMap<>(client.getClientSettings().getSettings());
        settingsMap.put(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING,
                hostedFor(clientId) + CONTENT_HASH_FRAGMENT);
        registeredClients.save(RegisteredClient.from(client)
                .clientSettings(org.springframework.security.oauth2.server.authorization.settings
                        .ClientSettings.withSettings(settingsMap).build())
                .build());
    }

    /** RFC 7591 section 3: an initial access token, spent by the registration it authorises. */
    @SuppressWarnings("unchecked")
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

    private String basicAuthHeader() {
        DemoProperties.Client registrar = properties.registrarClient();
        String credentials = registrar.clientId() + ":" + registrar.clientSecret();
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /** A browser with a session, pointing one client at one URL at a time. */
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

        private RegisteredRequestUriAttempt authorize(String label, String description,
                                                      String clientId, String requestUri,
                                                      boolean onTheList) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                    .queryParam(OAuth2ParameterNames.REQUEST_URI, requestUri)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new RegisteredRequestUriAttempt(label, description, clientId,
                                requestUri, onTheList, actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server acted on the request. A dynamically registered client asks for consent, and
     * that screen is built from the fetched object, so reaching it means the object was used.
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
}

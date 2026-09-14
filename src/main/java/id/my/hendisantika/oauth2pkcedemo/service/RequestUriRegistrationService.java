package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.HostedRequestObjectController;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriRegistrationAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriRegistrationRun;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 21.30
 */
@Slf4j
@Service
public class RequestUriRegistrationService {

    /** A URL this client never registered, and which this application hosts all the same. */
    public static final String UNREGISTERED_PATH = HostedRequestObjectController.OTHER_CLIENT_URI;

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final RequestUriPolicy policy;
    private final RegisteredClientRepository registeredClients;
    private final RestClient restClient;

    public RequestUriRegistrationService(DemoProperties properties, RequestUriPolicy policy,
                                         RegisteredClientRepository registeredClients) {
        this.properties = properties;
        this.policy = policy;
        this.registeredClients = registeredClients;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public DemoProperties.Client client() {
        return properties.fetchedRequestClient();
    }

    public boolean requireRegistration() {
        return this.policy.requireRegistration();
    }

    /** What this client registered, read from the registration rather than from the page. */
    public List<String> registeredUris() {
        RegisteredClient client = registeredClients.findByClientId(client().clientId());
        Object setting = client == null ? null : client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING);
        return setting == null ? List.of() : List.of(String.valueOf(setting).split("\\s+"));
    }

    /**
     * Four URLs, each sent twice: once with {@code require_request_uri_registration} on and once
     * with it off. Only one row changes, and the rest are the checks that do not depend on it.
     */
    public RequestUriRegistrationRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        String base = properties.issuerUri();
        List<String> uris = List.of(
                base + HostedRequestObjectController.HOSTED_URI,
                base + UNREGISTERED_PATH,
                base + HostedRequestObjectController.WRONG_TYPE_URI,
                base + HostedRequestObjectController.RECURSIVE_URI);
        List<Function<Probe, Outcome>> requests = uris.stream()
                .map(uri -> (Function<Probe, Outcome>) p -> p.authorize(uri))
                .toList();

        boolean previous = this.policy.requireRegistration(true);
        List<Outcome> whenRequired;
        List<Outcome> whenNot;
        String publishedWhenRequired;
        String publishedWhenNot;
        try {
            publishedWhenRequired = probe.publishedValue();
            whenRequired = requests.stream().map(request -> request.apply(probe)).toList();

            this.policy.requireRegistration(false);
            publishedWhenNot = probe.publishedValue();
            whenNot = requests.stream().map(request -> request.apply(probe)).toList();
        } finally {
            this.policy.requireRegistration(previous);
        }

        List<String> labels = List.of("A URL this client registered",
                "A URL another client registered", "A registered URL serving the wrong media type",
                "A registered URL whose object points at another");
        List<String> descriptions = List.of(
                "RFC 9101 §5.2: the server fetches it and uses what comes back.",
                "Hosted by this same application, and on somebody else's list.",
                "§10.4.1 clause (b): check the media type of the response.",
                "§4: a request object may not carry request or request_uri.");

        List<String> registered = registeredUris();
        List<RequestUriRegistrationAttempt> attempts = new ArrayList<>();
        for (int i = 0; i < uris.size(); i++) {
            attempts.add(new RequestUriRegistrationAttempt(labels.get(i), descriptions.get(i),
                    uris.get(i), registered.contains(uris.get(i)),
                    whenRequired.get(i).accepted(), whenRequired.get(i).outcome(),
                    whenNot.get(i).accepted(), whenNot.get(i).outcome()));
        }

        log.debug("request_uri registration run finished; {} rows changed with the setting",
                attempts.stream().filter(RequestUriRegistrationAttempt::changedWithTheSetting).count());
        return new RequestUriRegistrationRun(client().clientId(), registered, publishedWhenRequired,
                publishedWhenNot, this.policy.requireRegistration() == previous,
                List.copyOf(attempts), Instant.now());
    }

    /** One request's fate, before it is paired with the same request under the other setting. */
    private record Outcome(boolean accepted, String outcome) {
    }

    /** A browser with a session, and a reader of the published metadata. */
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

        private String publishedValue() {
            String document = restClient.get()
                    .uri("/.well-known/openid-configuration")
                    .retrieve().body(String.class);
            Matcher matcher = Pattern.compile("\""
                            + ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION
                            + "\"\\s*:\\s*(true|false)")
                    .matcher(document == null ? "" : document);
            return matcher.find() ? matcher.group(1) : "absent";
        }

        private Outcome authorize(String requestUri) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client().clientId())
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
                        return new Outcome(actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server acted on the request. Reaching the consent screen counts: it is built from
     * what the fetched object asked for, so getting there means the object was used.
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
            Matcher message = Pattern.compile("\"message\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
            if (message.find()) {
                return message.group(1);
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

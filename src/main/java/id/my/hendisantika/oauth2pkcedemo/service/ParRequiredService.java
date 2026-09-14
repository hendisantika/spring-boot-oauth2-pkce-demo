package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.ParRequiredAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.ParRequiredRun;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
 * Time: 22.40
 */
@Slf4j
@Service
public class ParRequiredService {

    /** A reference shaped like the ones this server issues, and issued by nobody. */
    public static final String INVENTED_REQUEST_URI =
            "urn:ietf:params:oauth:request_uri:invented-by-the-page";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RestClient restClient;

    public ParRequiredService(DemoProperties properties, JarRequestSigner signer) {
        this.properties = properties;
        this.signer = signer;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** The client that registered the lock. */
    public DemoProperties.Client requiredClient() {
        return properties.parRequiredClient();
    }

    /** The control: the same kind of client, without the registration. */
    public DemoProperties.Client ordinaryClient() {
        return properties.confidentialClient();
    }

    /**
     * Five authorization requests: the control's ordinary one, then four to the client that may only
     * start a request by pushing it.
     */
    public ParRequiredRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client required = requiredClient();
        List<ParRequiredAttempt> attempts = new ArrayList<>();

        attempts.add(probe.ordinary("An ordinary request, from a client that registered nothing",
                "The control, and what every page here that is not about PAR sends.",
                ordinaryClient()));
        attempts.add(probe.ordinary("An ordinary request",
                "The same parameters in the same query string, to the client that asked to be "
                        + "locked down.", required));
        attempts.add(probe.pushed("A pushed request, used at the authorization endpoint",
                "The one way in: client_id and the request_uri the push handed back.", required));
        attempts.add(probe.invented("A request_uri nobody issued",
                "Shaped like a real one. The filter here only asks whether it is present.",
                required));
        attempts.add(probe.requestObject("A signed request object instead",
                "JAR keeps the request from being tampered with; it does not keep it off the "
                        + "browser. They are different locks.", required));

        log.debug("PAR-required run finished; {} of {} accepted",
                attempts.stream().filter(ParRequiredAttempt::accepted).count(), attempts.size());
        return new ParRequiredRun(required.clientId(), ordinaryClient().clientId(),
                String.valueOf(publishedServerWide()), List.copyOf(attempts), Instant.now());
    }

    /** RFC 9126 section 5, read back from the document rather than from the constant. */
    public Object publishedServerWide() {
        Map<?, ?> document = restClient.get()
                .uri("/.well-known/oauth-authorization-server")
                .retrieve()
                .body(Map.class);
        Object value = document == null ? null
                : document.get(ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS);
        return value == null ? "absent" : value;
    }

    private Map<String, String> requestParameters(DemoProperties.Client client) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + client.registrationId());
        parameters.put(OAuth2ParameterNames.STATE, randomUrlSafe(16));
        parameters.put("code_challenge", codeChallenge(randomUrlSafe(32)));
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    /** RFC 9126 section 2: the parameters go to the back channel, authenticated. */
    @SuppressWarnings("unchecked")
    private String push(DemoProperties.Client client) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        requestParameters(client).forEach(form::add);

        Map<String, Object> body = restClient.post()
                .uri("/oauth2/par")
                .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(client))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        if (body == null || body.get(OAuth2ParameterNames.REQUEST_URI) == null) {
            throw new IllegalStateException("The pushed authorization request returned no request_uri");
        }
        return String.valueOf(body.get(OAuth2ParameterNames.REQUEST_URI));
    }

    private String basicAuthHeader(DemoProperties.Client client) {
        String credentials = client.clientId() + ":" + client.clientSecret();
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

        private ParRequiredAttempt ordinary(String label, String description,
                                            DemoProperties.Client client) {
            UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize");
            requestParameters(client).forEach(uri::queryParam);
            return get(label, description, client, "Every parameter, in the query string",
                    uri.build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private ParRequiredAttempt pushed(String label, String description,
                                          DemoProperties.Client client) {
            return withRequestUri(label, description, client, push(client));
        }

        private ParRequiredAttempt invented(String label, String description,
                                            DemoProperties.Client client) {
            return withRequestUri(label, description, client, INVENTED_REQUEST_URI);
        }

        private ParRequiredAttempt withRequestUri(String label, String description,
                                                  DemoProperties.Client client, String requestUri) {
            return get(label, description, client, "client_id and request_uri",
                    UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                            .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                            .queryParam(OAuth2ParameterNames.REQUEST_URI, requestUri)
                            .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private ParRequiredAttempt requestObject(String label, String description,
                                                 DemoProperties.Client client) {
            return get(label, description, client, "client_id and a signed request",
                    UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                            .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                            .queryParam("request", signer.sign(client.clientId(),
                                    properties.issuerUri(), requestParameters(client)))
                            .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private ParRequiredAttempt get(String label, String description,
                                       DemoProperties.Client client, String carried, String uri) {
            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        boolean accepted = actedOn(location);
                        String outcome = outcomeOf(location, body);
                        return new ParRequiredAttempt(label, description, client.clientId(),
                                client.clientId().equals(requiredClient().clientId()), carried,
                                accepted, accepted ? null : refusedBy(outcome), outcome);
                    }, false);
        }
    }

    /**
     * Which check spoke. The filter added here says so in as many words; anything else came from the
     * authorization server's own validation of the reference, which runs immediately after.
     */
    private static String refusedBy(String outcome) {
        return outcome.contains("require_pushed_authorization_requests")
                ? ParRequiredAttempt.THIS_FILTER
                : ParRequiredAttempt.THE_SERVER;
    }

    /**
     * Whether the server acted on the request. Reaching the consent screen counts: it is built from
     * what the request asked for, so getting there means the request was accepted.
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

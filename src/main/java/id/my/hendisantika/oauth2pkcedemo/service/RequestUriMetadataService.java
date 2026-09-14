package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriMetadataAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriMetadataRun;
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
 * Date: 17/09/26
 * Time: 16.05
 */
@Slf4j
@Service
public class RequestUriMetadataService {

    /** Where a client would host a request object for a server that fetches them. RFC 9101 §5.2. */
    public static final String HOSTED_REQUEST_OBJECT = "https://client.example.org/request-object.jwt";

    /** Shaped like one of this server's pushed references, and issued by nobody. */
    public static final String INVENTED_REFERENCE = "urn:ietf:params:oauth:request_uri:never-issued";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RestClient restClient;

    public RequestUriMetadataService(DemoProperties properties, JarRequestSigner signer) {
        this.properties = properties;
        this.signer = signer;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** The confidential client, because one of the four rows has to push. */
    public DemoProperties.Client client() {
        return properties.confidentialClient();
    }

    /** What OpenID Connect Discovery section 3 says each of these means when it is not published. */
    public Map<String, Object> defaultsIfOmitted() {
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put(ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED, false);
        defaults.put(ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED, true);
        defaults.put(ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION, false);
        return defaults;
    }

    /** The same three, as this server actually publishes them, read back from the document. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> published() {
        Map<String, Object> document = restClient.get()
                .uri("/.well-known/openid-configuration")
                .retrieve().body(Map.class);
        Map<String, Object> values = new LinkedHashMap<>();
        for (String name : defaultsIfOmitted().keySet()) {
            Object value = document == null ? null : document.get(name);
            values.put(name, value == null ? "absent" : value);
        }
        return values;
    }

    /**
     * Four authorization requests, one per way of referring to a request object: by value, by a URL
     * this server would have to fetch, by a reference the pushed endpoint issued, and by one that
     * looks like the last but was never issued.
     */
    public RequestUriMetadataRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client client = client();
        List<RequestUriMetadataAttempt> attempts = new ArrayList<>();

        String requestObject = signer.sign(client.clientId(), properties.issuerUri(),
                requestParameters(client));
        attempts.add(probe.send("By value", "RFC 9101 §5.1: the request object itself, in the URL.",
                JwtSecuredAuthorizationRequestFilter.REQUEST, requestObject,
                ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED + ": true"));
        attempts.add(probe.send("By a URL to fetch",
                "RFC 9101 §5.2: the client hosts the object and the server goes and gets it.",
                OAuth2ParameterNames.REQUEST_URI, HOSTED_REQUEST_OBJECT,
                ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED + ": false"));
        attempts.add(probe.send("By a pushed reference",
                "RFC 9126: the same parameter, carrying something the server handed out itself.",
                OAuth2ParameterNames.REQUEST_URI, push(client),
                ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED + ": false"));
        attempts.add(probe.send("By a reference nobody issued",
                "Shaped like the row above, and unknown to the server that would have issued it.",
                OAuth2ParameterNames.REQUEST_URI, INVENTED_REFERENCE,
                ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED + ": false"));

        log.debug("request_uri metadata run finished; {} of {} accepted",
                attempts.stream().filter(RequestUriMetadataAttempt::accepted).count(), attempts.size());
        return new RequestUriMetadataRun(published(), defaultsIfOmitted(), List.copyOf(attempts),
                Instant.now());
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

        private RequestUriMetadataAttempt send(String label, String description, String parameter,
                                               String value, String metadataSaid) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client().clientId())
                    .queryParam(parameter, value)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new RequestUriMetadataAttempt(label, description, parameter, value,
                                metadataSaid, actedOn(location), outcomeOf(location, body));
                    }, false);
        }
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

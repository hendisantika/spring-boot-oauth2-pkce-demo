package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.security.ServerParRequiredAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.ServerParRequiredRun;
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
 * Time: 08.15
 */
@Slf4j
@Service
public class ServerParRequiredService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final PushedAuthorizationPolicy policy;
    private final FapiComplianceService fapiComplianceService;
    private final RestClient restClient;

    public ServerParRequiredService(DemoProperties properties, JarRequestSigner signer,
                                    PushedAuthorizationPolicy policy,
                                    FapiComplianceService fapiComplianceService) {
        this.properties = properties;
        this.signer = signer;
        this.policy = policy;
        this.fapiComplianceService = fapiComplianceService;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public boolean requirePushedRequests() {
        return this.policy.requirePushedRequests();
    }

    /** The control: a confidential client that registered nothing about PAR. */
    public DemoProperties.Client ordinaryClient() {
        return properties.confidentialClient();
    }

    /** The one that locked its own door, from RFC 9126 section 6. */
    public DemoProperties.Client lockedClient() {
        return properties.parRequiredClient();
    }

    /**
     * The same four requests twice, once with the server-wide switch off and once with it on, with
     * the published document and the profile row read at each turn. The switch is global while it
     * is on and is put back in a finally block.
     */
    public ServerParRequiredRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<Function<Probe, Outcome>> requests = List.of(
                p -> p.ordinary(ordinaryClient()),
                p -> p.pushed(ordinaryClient()),
                p -> p.requestObject(ordinaryClient()),
                p -> p.ordinary(lockedClient()));

        boolean previous = this.policy.requirePushedRequests(false);
        List<Outcome> whenOff;
        List<Outcome> whenOn;
        String publishedWhenOff;
        String publishedWhenOn;
        String fapiWhenOff;
        String fapiWhenOn;
        try {
            publishedWhenOff = probe.publishedValue();
            fapiWhenOff = profileRow();
            whenOff = requests.stream().map(request -> request.apply(probe)).toList();

            this.policy.requirePushedRequests(true);
            publishedWhenOn = probe.publishedValue();
            fapiWhenOn = profileRow();
            whenOn = requests.stream().map(request -> request.apply(probe)).toList();
        } finally {
            this.policy.requirePushedRequests(previous);
        }

        List<String> labels = List.of("An ordinary authorization request", "A pushed request",
                "A signed request object", "An ordinary request, from the locked-down client");
        List<String> descriptions = List.of(
                "Every parameter in the query string, as OAuth 2.0 has always allowed.",
                "The same request, pushed first, with the browser carrying the reference.",
                "Tamper-proof, and still in the browser. A different lock entirely.",
                "Already refused before the switch was touched, by its own registration.");
        List<String> carried = List.of("every parameter", "client_id and request_uri",
                "client_id and a signed request", "every parameter");
        List<DemoProperties.Client> clients = List.of(ordinaryClient(), ordinaryClient(),
                ordinaryClient(), lockedClient());

        List<ServerParRequiredAttempt> attempts = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            attempts.add(new ServerParRequiredAttempt(labels.get(i), descriptions.get(i),
                    clients.get(i).clientId(),
                    clients.get(i).clientId().equals(lockedClient().clientId()), carried.get(i),
                    whenOff.get(i).accepted(), whenOff.get(i).outcome(),
                    whenOn.get(i).accepted(), whenOn.get(i).outcome()));
        }

        log.debug("Server PAR run finished; {} rows changed with the switch",
                attempts.stream().filter(ServerParRequiredAttempt::changedWithTheSwitch).count());
        return new ServerParRequiredRun(publishedWhenOff, publishedWhenOn, fapiWhenOff, fapiWhenOn,
                this.policy.requirePushedRequests() == previous, List.copyOf(attempts),
                Instant.now());
    }

    /**
     * What the FAPI page makes of the same requirement right now. It reads the running
     * configuration, so it answers differently on either side of the switch.
     */
    private String profileRow() {
        return fapiComplianceService.serverChecks().stream()
                .filter(check -> check.requirement().contains("requires pushed authorization requests"))
                .map(check -> check.outcome().name())
                .findFirst()
                .orElse("absent");
    }

    /** One request's fate, before it is paired with the same request under the other setting. */
    private record Outcome(boolean accepted, String outcome) {
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

    /** RFC 9126 section 2. The pushed endpoint is unaffected by the switch, and must be. */
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

        /** What the authorization server document says about itself right now. */
        private String publishedValue() {
            String document = browser.get()
                    .uri(base + "/.well-known/oauth-authorization-server")
                    .retrieve().body(String.class);
            Matcher matcher = Pattern.compile("\""
                            + ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS
                            + "\"\\s*:\\s*(true|false)")
                    .matcher(document == null ? "" : document);
            return matcher.find() ? matcher.group(1) : "absent";
        }

        private Outcome ordinary(DemoProperties.Client client) {
            UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize");
            requestParameters(client).forEach(uri::queryParam);
            return get(uri.build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private Outcome pushed(DemoProperties.Client client) {
            return get(UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam(OAuth2ParameterNames.REQUEST_URI, push(client))
                    .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private Outcome requestObject(DemoProperties.Client client) {
            return get(UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam("request", signer.sign(client.clientId(), properties.issuerUri(),
                            requestParameters(client)))
                    .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private Outcome get(String uri) {
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

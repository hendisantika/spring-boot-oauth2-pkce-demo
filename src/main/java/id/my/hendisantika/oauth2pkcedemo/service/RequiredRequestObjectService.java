package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.RequiredRequestAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequiredRequestRun;
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
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 17.20
 */
@Slf4j
@Service
public class RequiredRequestObjectService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RequestObjectPolicy policy;

    public RequiredRequestObjectService(DemoProperties properties, JarRequestSigner signer,
                                        RequestObjectPolicy policy) {
        this.properties = properties;
        this.signer = signer;
        this.policy = policy;
    }

    public boolean requireSignedRequestObject() {
        return this.policy.requireSignedRequestObject();
    }

    public DemoProperties.Client ordinaryClient() {
        return properties.client();
    }

    public DemoProperties.Client noneClient() {
        return properties.jarNoneClient();
    }

    public DemoProperties.Client strictClient() {
        return properties.jarNoneStrictClient();
    }

    /**
     * The same four requests twice: once with the server-wide switch off, once with it on. The
     * switch is global while it is on, and it is put back in a finally block - a deployment sets
     * this once in configuration rather than moving it under live traffic.
     */
    public RequiredRequestRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<Function<Probe, Outcome>> requests = List.of(
                p -> p.plain(ordinaryClient()),
                p -> p.signed(ordinaryClient()),
                p -> p.unsigned(noneClient()),
                p -> p.plain(strictClient()));

        boolean previous = this.policy.requireSignedRequestObject(false);
        List<Outcome> whenOff;
        List<Outcome> whenOn;
        String publishedWhenOff;
        String publishedWhenOn;
        try {
            publishedWhenOff = probe.publishedValue();
            whenOff = requests.stream().map(request -> request.apply(probe)).toList();

            this.policy.requireSignedRequestObject(true);
            publishedWhenOn = probe.publishedValue();
            whenOn = requests.stream().map(request -> request.apply(probe)).toList();
        } finally {
            this.policy.requireSignedRequestObject(previous);
        }

        List<String> labels = List.of(
                "An ordinary authorization request", "A signed request object",
                "An unsigned request object", "An ordinary request, from the strict client");
        List<String> descriptions = List.of(
                "No request object at all - the parameters in the query string, as OAuth 2.0 has "
                        + "always allowed.",
                "The same request, wrapped and signed as RFC 9101 asks.",
                "From the client that registered none, which the switch is aimed at.",
                "The same downgrade, refused by the client's own registration rather than the "
                        + "server's.");
        List<String> sent = List.of("No request object", "Signed request object",
                "Unsigned request object", "No request object");
        List<DemoProperties.Client> clients = List.of(ordinaryClient(), ordinaryClient(),
                noneClient(), strictClient());

        List<RequiredRequestAttempt> attempts = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            attempts.add(new RequiredRequestAttempt(labels.get(i), descriptions.get(i),
                    clients.get(i).clientId(), sent.get(i),
                    clients.get(i).clientId().equals(strictClient().clientId()),
                    whenOff.get(i).accepted(), whenOff.get(i).outcome(),
                    whenOn.get(i).accepted(), whenOn.get(i).outcome()));
        }

        log.debug("Required request object run finished; {} rows changed with the switch",
                attempts.stream().filter(RequiredRequestAttempt::changedWithTheSwitch).count());
        return new RequiredRequestRun(publishedWhenOff, publishedWhenOn,
                this.policy.requireSignedRequestObject() == previous, List.copyOf(attempts),
                Instant.now());
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

    /** A browser with a session, and a reader of the published metadata. */
    private final class Probe {

        private final RestClient restClient;
        private final String base = properties.issuerUri();

        private Probe() {
            HttpClient httpClient = HttpClient.newBuilder()
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            this.restClient = RestClient.builder()
                    .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                    .build();
        }

        private void signIn(String username, String password) {
            String page = restClient.get().uri(base + "/login").retrieve().body(String.class);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("username", username);
            form.add("password", password);
            form.add("_csrf", csrf(page));
            restClient.post()
                    .uri(base + "/login")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.getStatusCode().value(), false);
        }

        /** What the authorization server document says about itself right now. */
        private String publishedValue() {
            String document = restClient.get()
                    .uri(base + "/.well-known/oauth-authorization-server")
                    .retrieve().body(String.class);
            Matcher matcher = Pattern.compile("\""
                            + ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_METADATA
                            + "\"\\s*:\\s*(true|false)")
                    .matcher(document == null ? "" : document);
            return matcher.find() ? matcher.group(1) : "absent";
        }

        /** An RFC 6749 authorization request, with no request object anywhere in it. */
        private Outcome plain(DemoProperties.Client client) {
            UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize");
            requestParameters(client).forEach(uri::queryParam);
            return get(uri.build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private Outcome signed(DemoProperties.Client client) {
            return withRequestObject(client, signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client)));
        }

        private Outcome unsigned(DemoProperties.Client client) {
            return withRequestObject(client, signer.unsigned(client.clientId(),
                    properties.issuerUri(), requestParameters(client)));
        }

        private Outcome withRequestObject(DemoProperties.Client client, String requestObject) {
            return get(UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam("request", requestObject)
                    .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        private Outcome get(String uri) {
            return restClient.get()
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
     * the scopes the request asked for, so getting there means the request was accepted.
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

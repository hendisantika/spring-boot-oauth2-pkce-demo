package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWSAlgorithm;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.AdvertisedAlgAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.AdvertisedAlgRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
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
 * Date: 18/09/26
 * Time: 15.10
 */
@Slf4j
@Service
public class AdvertisedAlgService {

    /** The three lists RFC 9101 section 4 names together, in the order the page shows them. */
    public static final List<String> METADATA_NAMES = List.of(
            ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED,
            ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED,
            ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED);

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RestClient restClient;

    public AdvertisedAlgService(DemoProperties properties, JarRequestSigner signer) {
        this.properties = properties;
        this.signer = signer;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** The three lists as published, read back from the document rather than from the constants. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> published() {
        Map<String, Object> document;
        try {
            document = restClient.get()
                    .uri("/.well-known/openid-configuration")
                    .retrieve().body(Map.class);
        } catch (RuntimeException ex) {
            log.debug("Could not read the published document back: {}", ex.getMessage());
            document = null;
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (String name : METADATA_NAMES) {
            Object value = document == null ? null : document.get(name);
            values.put(name, value == null ? "unreachable" : value);
        }
        return values;
    }

    /** What the server says it will check, which is not the same as what any one client may send. */
    public List<String> advertisedSigningAlgs() {
        return JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream().sorted().toList();
    }

    /**
     * Five request objects, each signed with one algorithm, sent by whichever client registered it -
     * or, twice, by a client that did not.
     */
    public AdvertisedAlgRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<String> advertised = advertisedSigningAlgs();
        DemoProperties.Client rsa = properties.client();
        DemoProperties.Client ps = properties.jarPsClient();
        DemoProperties.Client none = properties.jarNoneClient();
        DemoProperties.Client es = properties.jarEsClient();

        List<AdvertisedAlgAttempt> attempts = new ArrayList<>();
        attempts.add(probe.signed("RS256, by the client that registered it",
                "On the list, and the one this client named.", rsa, "RS256", "RS256",
                advertised.contains("RS256"), JWSAlgorithm.RS256));
        attempts.add(probe.signed("PS256, by the same client",
                "Also on the list. The list is the server's, not this client's.", rsa, "RS256",
                "PS256", advertised.contains("PS256"), JWSAlgorithm.PS256));
        attempts.add(probe.signed("PS256, by the client that registered it",
                "Same algorithm, same list, different registration.", ps, "PS256", "PS256",
                advertised.contains("PS256"), JWSAlgorithm.PS256));
        attempts.add(probe.unsigned("none, by the client that registered it",
                "The list says none is a value this server checks for, which is to say does not.",
                none, "none", advertised.contains("none")));
        attempts.add(probe.elliptic("ES256, by the client that registered it",
                "A real JWS algorithm, a key this client publishes, and not on the list.",
                es, "ES256", advertised.contains("ES256")));

        log.debug("Advertised algorithm run finished; {} of {} accepted",
                attempts.stream().filter(AdvertisedAlgAttempt::accepted).count(), attempts.size());
        return new AdvertisedAlgRun(published(), List.copyOf(attempts), Instant.now());
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

    /** A browser with a session, carrying one request object at a time. */
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

        private AdvertisedAlgAttempt signed(String label, String description,
                                            DemoProperties.Client client, String registeredAlg,
                                            String sentAlg, boolean advertised,
                                            JWSAlgorithm algorithm) {
            return send(label, description, client, registeredAlg, sentAlg, advertised,
                    signer.sign(client.clientId(), properties.issuerUri(),
                            requestParameters(client), algorithm));
        }

        private AdvertisedAlgAttempt unsigned(String label, String description,
                                              DemoProperties.Client client, String registeredAlg,
                                              boolean advertised) {
            return send(label, description, client, registeredAlg, "none", advertised,
                    signer.unsigned(client.clientId(), properties.issuerUri(),
                            requestParameters(client)));
        }

        private AdvertisedAlgAttempt elliptic(String label, String description,
                                              DemoProperties.Client client, String registeredAlg,
                                              boolean advertised) {
            return send(label, description, client, registeredAlg, "ES256", advertised,
                    signer.signWithEllipticCurve(client.clientId(), properties.issuerUri(),
                            requestParameters(client)));
        }

        private AdvertisedAlgAttempt send(String label, String description,
                                          DemoProperties.Client client, String registeredAlg,
                                          String sentAlg, boolean advertised, String requestObject) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam("request", requestObject)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new AdvertisedAlgAttempt(label, description, client.clientId(),
                                registeredAlg, sentAlg, advertised, actedOn(location),
                                outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server acted on the request. Reaching the consent screen counts: that screen is
     * built from the object's own scopes.
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

package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWSAlgorithm;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.SigningAlgAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.SigningAlgRun;
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
 * Time: 06.10
 */
@Slf4j
@Service
public class RequestObjectSigningAlgService {

    /** What an unsigned request object's header says where an algorithm should be. */
    public static final String NO_ALGORITHM = "none";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;

    public RequestObjectSigningAlgService(DemoProperties properties, JarRequestSigner signer) {
        this.properties = properties;
        this.signer = signer;
    }

    /** The client that registered nothing, and so registered the default. */
    public DemoProperties.Client defaultAlgClient() {
        return properties.client();
    }

    /** The client that registered PS256. */
    public DemoProperties.Client ps256Client() {
        return properties.jarPsClient();
    }

    /**
     * The same request object signed five ways: each client signing with what it registered, each
     * signing with the other algorithm, and one not signed at all.
     */
    public SigningAlgRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client rsaClient = defaultAlgClient();
        DemoProperties.Client psClient = ps256Client();

        List<SigningAlgAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize("Signed with what it registered", rsaClient,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG, JWSAlgorithm.RS256));
        attempts.add(probe.authorize("The same key, the other padding", rsaClient,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG, JWSAlgorithm.PS256));
        attempts.add(probe.authorize("Signed with what it registered", psClient,
                "PS256", JWSAlgorithm.PS256));
        attempts.add(probe.authorize("The algorithm the other client registered", psClient,
                "PS256", JWSAlgorithm.RS256));
        attempts.add(probe.unsigned("Not signed at all", rsaClient,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG));

        log.debug("Signing algorithm run finished; {} of {} accepted",
                attempts.stream().filter(SigningAlgAttempt::accepted).count(), attempts.size());
        return new SigningAlgRun(JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG,
                List.copyOf(JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream()
                        .sorted().toList()),
                List.copyOf(attempts), Instant.now());
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

        private SigningAlgAttempt authorize(String label, DemoProperties.Client client,
                                            String registeredAlg, JWSAlgorithm algorithm) {
            String requestObject = signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client), algorithm);
            return send(label, client, registeredAlg, algorithm.getName(), requestObject);
        }

        private SigningAlgAttempt unsigned(String label, DemoProperties.Client client,
                                           String registeredAlg) {
            String requestObject = signer.unsigned(client.clientId(), properties.issuerUri(),
                    requestParameters(client));
            return send(label, client, registeredAlg, NO_ALGORITHM, requestObject);
        }

        /**
         * RFC 9101 section 5: the URL carries a client id and the object, and the object carries
         * everything else - including, in its header, the algorithm it claims to be signed with.
         */
        private SigningAlgAttempt send(String label, DemoProperties.Client client,
                                       String registeredAlg, String sentAlg, String requestObject) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam("request", requestObject)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new SigningAlgAttempt(label, client.clientId(), registeredAlg,
                                sentAlg, actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server used the object's parameters. Reaching the consent screen counts: that
     * screen is built from the scopes the object asked for, so getting there means the object was
     * verified and acted on.
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
                return "the consent screen, built from the object's own scopes";
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

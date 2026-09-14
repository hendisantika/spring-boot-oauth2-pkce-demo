package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmAlgorithmAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.JarmAlgorithmRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
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
import java.net.URLDecoder;
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
 * Date: 15/09/26
 * Time: 14.20
 */
@Slf4j
@Service
public class JarmAlgorithmService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JwtDecoder jwtDecoder;
    private final JWKSource<SecurityContext> jwkSource;
    private final RegisteredClientRepository registeredClientRepository;
    private final JarmResponseFilter algorithms;

    public JarmAlgorithmService(DemoProperties properties, JwtDecoder jwtDecoder,
                                JWKSource<SecurityContext> jwkSource,
                                RegisteredClientRepository registeredClientRepository) {
        this.properties = properties;
        this.jwtDecoder = jwtDecoder;
        this.jwkSource = jwkSource;
        this.registeredClientRepository = registeredClientRepository;
        // The same resolution the filter uses, asked directly: the page should not have a second
        // opinion about what a registration means.
        this.algorithms = new JarmResponseFilter("/oauth2/authorize", registeredClientRepository,
                null, properties.issuerUri());
    }

    /**
     * The same authorization request from three clients that differ in one setting: the algorithm
     * their authorization responses are to be signed with.
     */
    public JarmAlgorithmRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<JarmAlgorithmAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize(properties.jarmClient()));
        attempts.add(probe.authorize(properties.jarmEcClient()));
        attempts.add(probe.authorize(properties.jarmNoneClient()));

        log.debug("JARM algorithm run finished with {} attempts", attempts.size());
        return new JarmAlgorithmRun(List.copyOf(attempts), publishedKeys(), Instant.now());
    }

    /** What the registration says, verbatim - {@code null} when it says nothing. */
    public String registeredAlgorithm(DemoProperties.Client client) {
        RegisteredClient registered = registeredClientRepository.findByClientId(client.clientId());
        Object configured = registered == null ? null
                : registered.getClientSettings().getSetting(JarmResponseFilter.SIGNED_RESPONSE_ALG);
        return configured == null ? null : String.valueOf(configured);
    }

    /** The keys the server publishes, so the page can show which one carried which answer. */
    private Map<String, String> publishedKeys() {
        Map<String, String> keys = new LinkedHashMap<>();
        try {
            for (JWK jwk : jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null)) {
                keys.put(jwk.getKeyID(), jwk.getKeyType().getValue());
            }
        } catch (Exception ex) {
            log.debug("Unable to read the published keys: {}", ex.getMessage());
        }
        return keys;
    }

    /** A browser with a session, asking each client's authorization request in turn. */
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

        private JarmAlgorithmAttempt authorize(DemoProperties.Client client) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()))
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI, base + JarmController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, randomUrlSafe(16))
                    .queryParam("code_challenge", codeChallenge(randomUrlSafe(32)))
                    .queryParam("code_challenge_method", "S256")
                    .queryParam(JarmResponseFilter.RESPONSE_MODE, "jwt")
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            String location = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);

            String registeredAs = registeredAlgorithm(client);
            String resolvedTo = algorithms.algorithmFor(client.clientId());
            String jwt = location == null ? null : parameterOf(location, JarmResponseFilter.RESPONSE);
            if (jwt == null) {
                return new JarmAlgorithmAttempt(client.clientId(), registeredAs, resolvedTo, null,
                        null, false, null,
                        location == null ? "no answer" : parameterOf(location, OAuth2ParameterNames.ERROR));
            }
            try {
                var decoded = jwtDecoder.decode(jwt);
                return new JarmAlgorithmAttempt(client.clientId(), registeredAs, resolvedTo,
                        String.valueOf(decoded.getHeaders().get("alg")),
                        String.valueOf(decoded.getHeaders().get("kid")), true, true, null);
            } catch (Exception ex) {
                log.debug("A {} response did not verify: {}", resolvedTo, ex.getMessage());
                return new JarmAlgorithmAttempt(client.clientId(), registeredAs, resolvedTo, null,
                        null, true, false, ex.getMessage());
            }
        }
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page == null ? "" : page);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String parameterOf(String uri, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(uri);
        return matcher.find() ? URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
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

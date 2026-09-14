package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWEObject;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmClientKeys;
import id.my.hendisantika.oauth2pkcedemo.security.JarmEncryptionMethodAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.JarmEncryptionMethodRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
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
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 20.40
 */
@Slf4j
@Service
public class JarmEncryptionMethodService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarmClientKeys clientKeys;
    private final RegisteredClientRepository registeredClientRepository;
    private final JarmResponseFilter methods;

    public JarmEncryptionMethodService(DemoProperties properties, JarmClientKeys clientKeys,
                                       RegisteredClientRepository registeredClientRepository) {
        this.properties = properties;
        this.clientKeys = clientKeys;
        this.registeredClientRepository = registeredClientRepository;
        this.methods = new JarmResponseFilter("/oauth2/authorize", registeredClientRepository, null,
                properties.issuerUri());
    }

    public List<String> supported() {
        return JarmResponseFilter.SUPPORTED_ENCRYPTION_METHODS.stream().sorted().toList();
    }

    public String defaultMethod() {
        return JarmResponseFilter.DEFAULT_ENCRYPTION_METHOD;
    }

    /**
     * Three registrations that differ only in {@code enc}: one that leaves it out, one that names a
     * method with a different shape, and one that names a method this server does not offer.
     */
    public JarmEncryptionMethodRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<JarmEncryptionMethodAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize(properties.jarmEncryptedClient()));
        attempts.add(probe.authorize(properties.jarmGcmClient()));
        attempts.add(probe.authorize(properties.jarmUnsupportedEncClient()));

        // Each run is a separate authorization, so the payloads carry their own code and state. What
        // is the same every time is what they are: a three-part signed JWT, which is the only thing
        // enc has no say over at all.
        boolean allSignedJwts = !probe.plaintexts.isEmpty()
                && probe.plaintexts.stream().allMatch(jwt -> jwt.split("\\.").length == 3);

        log.debug("JARM enc run finished; {} of {} encrypted", attempts.stream()
                .filter(JarmEncryptionMethodAttempt::encrypted).count(), attempts.size());
        return new JarmEncryptionMethodRun(List.copyOf(attempts), allSignedJwts, Instant.now());
    }

    /** A browser with a session, asking each registration in turn. */
    private final class Probe {

        private final RestClient restClient;
        private final String base = properties.issuerUri();
        private final List<String> plaintexts = new ArrayList<>();

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

        private JarmEncryptionMethodAttempt authorize(DemoProperties.Client client) {
            RegisteredClient registered = registeredClientRepository.findByClientId(client.clientId());
            Object configured = registered.getClientSettings()
                    .getSetting(JarmResponseFilter.ENCRYPTED_RESPONSE_ENC);
            String registeredAs = configured == null ? null : String.valueOf(configured);
            String resolvedTo = methods.encryptionMethodFor(registered);

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

            String response = location == null ? null
                    : parameterOf(location, JarmResponseFilter.RESPONSE);
            String[] parts = response == null ? new String[0] : response.split("\\.");
            if (parts.length != 5) {
                return new JarmEncryptionMethodAttempt(client.clientId(), registeredAs, resolvedTo,
                        null, 0, 0, 0, 0, 0, false,
                        location == null ? "no answer"
                                : parameterOf(location, OAuth2ParameterNames.ERROR));
            }

            String plaintext = clientKeys.decrypt(response);
            plaintexts.add(plaintext);
            String headerMethod;
            try {
                headerMethod = JWEObject.parse(response).getHeader().getEncryptionMethod().getName();
            } catch (Exception ex) {
                headerMethod = null;
            }
            return new JarmEncryptionMethodAttempt(client.clientId(), registeredAs, resolvedTo,
                    headerMethod, parts[1].length(), parts[2].length(), parts[3].length(),
                    parts[4].length(), plaintext.length(), true, null);
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
